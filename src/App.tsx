import { useEffect, useRef, useState, Fragment } from "react";
import {
  maskOutput,
  DEFAULT_MASK_OPTIONS,
  type MaskResult,
  type Mapping,
  type SourceType,
} from "./lib/pentect";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Copy, Check } from "lucide-react";

const SAMPLES: Record<SourceType, string> = {
  env: `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
JIRA_BASE_URL=https://jira.corp.internal/rest/api/2/search
SUPPORT_EMAIL=secops@example.com
FEATURE_FLAG=true`,
  nmap: `Nmap scan report for db-internal-01 (10.0.1.5)
Host is up (0.0012s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9
3306/tcp  open  mysql   MySQL 8.0.32
33060/tcp open  mysqlx  MySQL X Protocol

Nmap scan report for gateway.corp.internal (10.0.1.1)
Host is up (0.0008s latency).

PORT    STATE SERVICE
22/tcp  open  ssh
443/tcp open  https
389/tcp open  ldap`,
  har: `{
  "log": {
    "entries": [
      {
        "request": {
          "method": "GET",
          "url": "https://jira.corp.internal/rest/api/2/search?jql=project=SEC",
          "headers": [
            { "name": "Authorization", "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sample.token" },
            { "name": "Cookie", "value": "JSESSIONID=ABCD1234EFGH5678; csrftoken=qwertyuiopasdfgh" }
          ]
        },
        "response": {
          "headers": [
            { "name": "Set-Cookie", "value": "JSESSIONID=ABCD1234EFGH5678; Path=/; Secure" }
          ]
        }
      }
    ]
  }
}`,
};

const CONFIDENCE_COLORS: Record<
  string,
  { bg: string; text: string; border: string; badge: string }
> = {
  HIGH: {
    bg: "bg-emerald-100",
    text: "text-emerald-800",
    border: "border-emerald-300",
    badge: "bg-emerald-600 text-white",
  },
  LIKELY: {
    bg: "bg-amber-100",
    text: "text-amber-800",
    border: "border-amber-300",
    badge: "bg-amber-500 text-white",
  },
  MAYBE: {
    bg: "bg-orange-100",
    text: "text-orange-800",
    border: "border-orange-300",
    badge: "bg-orange-500 text-white",
  },
  UNKNOWN: {
    bg: "bg-zinc-100",
    text: "text-zinc-700",
    border: "border-zinc-300",
    badge: "bg-zinc-500 text-white",
  },
};

const MAX_SCAN_STEPS = 18;
const ANIMATION_TOTAL_MS = 9200;

interface OutputFrame {
  text: string;
  activeLabels: string[];
  tableMappings: Mapping[];
  scanStartLine: number | null;
  scanEndLine: number | null;
}

function lineIndexAtOffset(text: string, offset: number): number {
  if (offset <= 0) return 0;
  return text.slice(0, offset).split(/\r?\n/).length - 1;
}

function parseLabelParts(label: string): { prefix: string; number: number } | null {
  const match = label.match(/^<<([A-Z]+)_(\d+)>>$/);
  if (!match) return null;

  return {
    prefix: match[1],
    number: Number.parseInt(match[2], 10),
  };
}

function replaceSorted(text: string, replacements: Array<[string, string]>): string {
  let result = text;
  const sorted = [...replacements].sort((left, right) => right[0].length - left[0].length);

  for (const [from, to] of sorted) {
    if (!from || from === to) continue;
    result = result.split(from).join(to);
  }

  return result;
}

function buildScanRanges(
  totalLines: number,
  maxSteps: number
): Array<{ start: number; end: number }> {
  if (totalLines <= 0) return [];

  const chunkSize = Math.max(1, Math.ceil(totalLines / maxSteps));
  const ranges: Array<{ start: number; end: number }> = [];

  for (let start = 0; start < totalLines; start += chunkSize) {
    ranges.push({
      start,
      end: Math.min(totalLines - 1, start + chunkSize - 1),
    });
  }

  return ranges;
}

function buildLineDiffRange(
  previousText: string,
  nextText: string
): { prefix: number; suffix: number; changedCount: number } {
  const previousLines = previousText.split(/\r?\n/);
  const nextLines = nextText.split(/\r?\n/);
  let prefix = 0;

  while (
    prefix < previousLines.length &&
    prefix < nextLines.length &&
    previousLines[prefix] === nextLines[prefix]
  ) {
    prefix += 1;
  }

  let suffix = 0;
  while (
    suffix < previousLines.length - prefix &&
    suffix < nextLines.length - prefix &&
    previousLines[previousLines.length - 1 - suffix] ===
      nextLines[nextLines.length - 1 - suffix]
  ) {
    suffix += 1;
  }

  return {
    prefix,
    suffix,
    changedCount: Math.max(0, nextLines.length - prefix - suffix),
  };
}

function renderHighlightedFragments(
  text: string,
  mappings: Mapping[],
  activeLabels: string[],
  keyPrefix: string
) {
  const parts: Array<{ text: string; isToken: boolean }> = [];
  const regex = tokenRegex();
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push({ text: text.slice(lastIndex, match.index), isToken: false });
    }
    parts.push({ text: match[0], isToken: true });
    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < text.length) {
    parts.push({ text: text.slice(lastIndex), isToken: false });
  }

  return parts.map((part, index) => {
    if (!part.isToken) return <Fragment key={`${keyPrefix}:${index}`}>{part.text}</Fragment>;

    const mapping = getMapping(part.text, mappings);
    const colors = CONFIDENCE_COLORS[mapping?.confidence ?? "UNKNOWN"];
    const isActive = mapping !== undefined && activeLabels.includes(mapping.label);

    return (
      <span
        key={`${keyPrefix}:${index}`}
        title={mapping ? `${mapping.original} | ${mapping.reason}` : part.text}
        className={`inline px-1 py-0.5 rounded-sm border font-semibold transition-all duration-300 ${colors.bg} ${colors.text} ${colors.border} ${
          isActive ? "ring-1 ring-amber-500 shadow-sm shadow-amber-200" : ""
        }`}
      >
        {part.text}
      </span>
    );
  });
}

function tokenRegex(): RegExp {
  return /<<[^>]+>>/g;
}

function getMapping(label: string, mappings: Mapping[]): Mapping | undefined {
  return mappings.find((entry) => entry.label === label);
}

function HighlightedOutput({
  text,
  mappings,
  activeLabels,
  scanStartLine,
  scanEndLine,
}: {
  text: string;
  mappings: Mapping[];
  activeLabels: string[];
  scanStartLine: number | null;
  scanEndLine: number | null;
}) {
  const lines = text.split(/\r?\n/);

  return (
    <pre className="m-0 whitespace-pre-wrap break-all font-mono text-[13px] leading-6">
      {lines.map((line, index) => {
        const isScanning =
          scanStartLine !== null &&
          scanEndLine !== null &&
          index >= scanStartLine &&
          index <= scanEndLine;

        return (
          <span
            key={index}
            className={`relative block px-1 transition-colors duration-300 ${
              isScanning ? "bg-amber-100" : ""
            }`}
          >
            <span className="relative">
              {renderHighlightedFragments(line, mappings, activeLabels, `line-${index}`)}
            </span>
          </span>
        );
      })}
    </pre>
  );
}

function placeholderFor(sourceType: SourceType): string {
  if (sourceType === "env") return ".env や設定ファイルを貼り付け...";
  if (sourceType === "nmap") return "nmap などの調査ログを貼り付け...";
  return "HAR を貼り付け...";
}

function buildOutputBody(maskedText: string): string {
  return maskedText.trim();
}

function setCaptureReady(ready: boolean): void {
  document.documentElement.dataset.pentectReady = ready ? "true" : "false";
}

function reconcileResultLabels(
  nextResult: MaskResult,
  previousResult: MaskResult | null
): MaskResult {
  if (!previousResult) return nextResult;

  const previousByOriginal = new Map(
    previousResult.mappingTable.map((mapping) => [mapping.original, mapping])
  );
  const usedLabels = new Set<string>();
  const counters = new Map<string, number>();

  for (const mapping of previousResult.mappingTable) {
    const parts = parseLabelParts(mapping.label);
    if (!parts) continue;
    counters.set(parts.prefix, Math.max(counters.get(parts.prefix) ?? 0, parts.number));
  }

  const replacements: Array<[string, string]> = [];
  const remappedMappings = nextResult.mappingTable.map((mapping) => {
    const currentParts = parseLabelParts(mapping.label);
    const previous = previousByOriginal.get(mapping.original);
    let nextLabel = mapping.label;

    if (previous && !usedLabels.has(previous.label)) {
      const previousParts = parseLabelParts(previous.label);
      if (
        currentParts &&
        previousParts &&
        currentParts.prefix === previousParts.prefix
      ) {
        nextLabel = previous.label;
      }
    }

    if (usedLabels.has(nextLabel)) {
      const prefix = currentParts?.prefix ?? "VALUE";
      const nextNumber = (counters.get(prefix) ?? 0) + 1;
      counters.set(prefix, nextNumber);
      nextLabel = `<<${prefix}_${String(nextNumber).padStart(3, "0")}>>`;
    } else if (currentParts) {
      counters.set(
        currentParts.prefix,
        Math.max(counters.get(currentParts.prefix) ?? 0, currentParts.number)
      );
    }

    usedLabels.add(nextLabel);
    replacements.push([mapping.label, nextLabel]);

    return {
      ...mapping,
      label: nextLabel,
    };
  });

  return {
    ...nextResult,
    masked: replaceSorted(nextResult.masked, replacements),
    aiBundle: replaceSorted(nextResult.aiBundle, replacements),
    mappingTable: remappedMappings,
  };
}

function buildDiffOutputFrames(
  previousInput: string | null,
  nextInput: string,
  previousResult: MaskResult | null,
  nextResult: MaskResult
): OutputFrame[] {
  const initialText = previousResult
    ? buildOutputBody(previousResult.masked)
    : buildOutputBody(nextInput);
  const finalText = buildOutputBody(nextResult.masked);
  const initialLines = initialText.split(/\r?\n/);
  const finalLines = finalText.split(/\r?\n/);
  const previousLabels = previousResult?.mappingTable ?? [];
  const inputChanged = previousInput !== null && previousInput !== nextInput;
  const nextOrder = new Map(
    nextResult.mappingTable.map((mapping, index) => [mapping.label, index])
  );
  const nextLineMappings = nextResult.mappingTable
    .map((mapping, order) => {
      const firstIndex = nextInput.indexOf(mapping.original);
      return {
        mapping,
        order,
        firstIndex,
        lineIndex:
          firstIndex === -1
            ? Number.MAX_SAFE_INTEGER
            : lineIndexAtOffset(nextInput, firstIndex),
      };
    })
    .sort((left, right) => {
      const leftIndex =
        left.firstIndex === -1 ? Number.MAX_SAFE_INTEGER : left.firstIndex;
      const rightIndex =
        right.firstIndex === -1 ? Number.MAX_SAFE_INTEGER : right.firstIndex;

      return (
        leftIndex - rightIndex ||
        right.mapping.original.length - left.mapping.original.length ||
        left.order - right.order
      );
    });
  const diffRange = previousResult
    ? buildLineDiffRange(previousInput ?? "", nextInput)
    : {
        prefix: 0,
        suffix: 0,
        changedCount: finalLines.length,
      };
  const scanRanges =
    diffRange.changedCount > 0
      ? buildScanRanges(diffRange.changedCount, MAX_SCAN_STEPS).map((range) => ({
          start: diffRange.prefix + range.start,
          end: diffRange.prefix + range.end,
        }))
      : [];
  const frames: OutputFrame[] = [];
  const visibleMappings = new Map(previousLabels.map((mapping) => [mapping.label, mapping]));

  for (const range of scanRanges) {
    const newLabels: string[] = [];

    for (const entry of nextLineMappings) {
      if (entry.lineIndex < range.start || entry.lineIndex > range.end) continue;

      const previousVisible = visibleMappings.get(entry.mapping.label);
      const mappingChanged =
        !previousVisible ||
        previousVisible.original !== entry.mapping.original ||
        previousVisible.confidence !== entry.mapping.confidence ||
        previousVisible.reason !== entry.mapping.reason;

      if (!mappingChanged) continue;

      visibleMappings.set(entry.mapping.label, entry.mapping);
      newLabels.push(entry.mapping.label);
    }

    const scannedCount = range.end - diffRange.prefix + 1;
    const previousChangeEnd = initialLines.length - diffRange.suffix;
    const nextChangeEnd = finalLines.length - diffRange.suffix;
    const currentLines = [
      ...finalLines.slice(0, diffRange.prefix + scannedCount),
      ...initialLines.slice(
        Math.min(diffRange.prefix + scannedCount, previousChangeEnd),
        previousChangeEnd
      ),
      ...finalLines.slice(nextChangeEnd),
    ];

    frames.push({
      text: currentLines.join("\n"),
      activeLabels: newLabels,
      tableMappings: [...visibleMappings.values()].sort((left, right) => {
        return (
          (nextOrder.get(left.label) ?? Number.MAX_SAFE_INTEGER) -
          (nextOrder.get(right.label) ?? Number.MAX_SAFE_INTEGER)
        );
      }),
      scanStartLine: range.start,
      scanEndLine: range.end,
    });
  }

  frames.push({
    text: finalText,
    activeLabels: [],
    tableMappings: nextResult.mappingTable,
    scanStartLine: null,
    scanEndLine: null,
  });

  if (!previousResult) {
    return frames;
  }

  return inputChanged ? frames : [frames[frames.length - 1]];
}

export default function App() {
  const [sourceType, setSourceType] = useState<SourceType>("env");
  const [input, setInput] = useState(SAMPLES.env);
  const [result, setResult] = useState<MaskResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [displayText, setDisplayText] = useState(buildOutputBody(SAMPLES.env));
  const [activeLabels, setActiveLabels] = useState<string[]>([]);
  const [tableMappings, setTableMappings] = useState<Mapping[]>([]);
  const [scanStartLine, setScanStartLine] = useState<number | null>(0);
  const [scanEndLine, setScanEndLine] = useState<number | null>(0);
  const animationTimers = useRef<number[]>([]);
  const previousResultRef = useRef<MaskResult | null>(null);
  const previousInputRef = useRef<string | null>(null);
  const previousSourceTypeRef = useRef<SourceType>("env");

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (!input.trim()) {
        setResult(null);
        return;
      }

      try {
        const previousResult =
          previousSourceTypeRef.current === sourceType
            ? previousResultRef.current
            : null;
        const stableResult = reconcileResultLabels(
          maskOutput(input, sourceType, DEFAULT_MASK_OPTIONS),
          previousResult
        );
        setResult(stableResult);
      } catch {
        setResult(null);
      }
    }, 180);

    return () => window.clearTimeout(timer);
  }, [input, sourceType]);

  useEffect(() => {
    animationTimers.current.forEach((timer) => window.clearTimeout(timer));
    animationTimers.current = [];

    const applyFrame = (frame: OutputFrame) => {
      setDisplayText(frame.text);
      setActiveLabels(frame.activeLabels);
      setTableMappings(frame.tableMappings);
      setScanStartLine(frame.scanStartLine);
      setScanEndLine(frame.scanEndLine);
    };

    if (!result) {
      setCaptureReady(false);
      const timeoutId = window.setTimeout(() => {
        applyFrame({
          text: buildOutputBody(input),
          activeLabels: [],
          tableMappings: [],
          scanStartLine: null,
          scanEndLine: null,
        });
        previousResultRef.current = null;
        previousInputRef.current = input;
        previousSourceTypeRef.current = sourceType;
        setCaptureReady(true);
      }, 0);

      animationTimers.current.push(timeoutId);

      return;
    }

    const previousResult =
      previousSourceTypeRef.current === sourceType ? previousResultRef.current : null;
    const previousInput =
      previousSourceTypeRef.current === sourceType ? previousInputRef.current : null;
    const frames = buildDiffOutputFrames(previousInput, input, previousResult, result);
    const intervalMs = Math.max(
      480,
      Math.min(900, Math.floor(ANIMATION_TOTAL_MS / Math.max(frames.length, 1)))
    );

    setCaptureReady(false);

    frames.forEach((frame, index) => {
      const timeoutId = window.setTimeout(() => {
        applyFrame(frame);

        if (index === frames.length - 1) {
          previousResultRef.current = result;
          previousInputRef.current = input;
          previousSourceTypeRef.current = sourceType;
          setCaptureReady(true);
        }
      }, 520 + intervalMs * index);

      animationTimers.current.push(timeoutId);
    });

    return () => {
      animationTimers.current.forEach((timer) => window.clearTimeout(timer));
      animationTimers.current = [];
    };
  }, [input, result, sourceType]);

  const handleCopy = async () => {
    if (!result) return;
    await navigator.clipboard.writeText(buildOutputBody(result.masked));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  };

  const loadSource = (nextSource: SourceType) => {
    setSourceType(nextSource);
    setInput(SAMPLES[nextSource]);
    setCaptureReady(false);
  };

  return (
    <div className="min-h-screen bg-background">
      <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
        <section className="mb-5 flex justify-end">
          <div className="flex flex-wrap items-center gap-2">
            {(["env", "nmap", "har"] as const).map((value) => (
              <button
                key={value}
                onClick={() => loadSource(value)}
                className={`rounded-full border px-3 py-1 text-xs transition-colors ${
                  sourceType === value
                    ? "border-foreground bg-foreground text-background"
                    : "border-border text-muted-foreground hover:border-foreground/50 hover:text-foreground"
                }`}
              >
                {value.toUpperCase()}
              </button>
            ))}
          </div>
        </section>

        <section className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="rounded-2xl border border-border bg-card p-4">
            <div className="mb-2 flex items-center justify-between">
              <h2 className="text-sm font-medium tracking-tight">入力</h2>
            </div>
            <Textarea
              value={input}
              onChange={(event) => {
                setInput(event.target.value);
                setCaptureReady(false);
              }}
              placeholder={placeholderFor(sourceType)}
              spellCheck={false}
              className="min-h-[260px] resize-none bg-muted/30 font-mono text-[13px] leading-relaxed sm:min-h-[460px]"
            />
          </div>

          <div className="rounded-2xl border border-border bg-card p-4">
            <div className="mb-2 flex items-center justify-between">
              <h2 className="text-sm font-medium tracking-tight">出力</h2>
              <Button
                variant="ghost"
                size="sm"
                onClick={handleCopy}
                disabled={!result}
                className="h-8 px-2 text-xs"
              >
                {copied ? (
                  <Check className="mr-1 h-3.5 w-3.5" />
                ) : (
                  <Copy className="mr-1 h-3.5 w-3.5" />
                )}
                {copied ? "コピー済み" : "コピー"}
              </Button>
            </div>
            <div className="min-h-[260px] overflow-auto rounded-xl border border-input bg-muted/30 p-3 sm:min-h-[460px]">
              {displayText ? (
                <HighlightedOutput
                  text={displayText}
                  mappings={tableMappings}
                  activeLabels={activeLabels}
                  scanStartLine={scanStartLine}
                  scanEndLine={scanEndLine}
                />
              ) : (
                <div />
              )}
            </div>
          </div>
        </section>

        <section className="mt-5 rounded-2xl border border-border bg-card p-4">
          <div className="min-h-[220px] overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/30">
                  <TableHead className="w-[180px] text-xs">ラベル</TableHead>
                  <TableHead className="text-xs">元の値</TableHead>
                  <TableHead className="w-[100px] text-xs">確信度</TableHead>
                  <TableHead className="text-xs">理由</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tableMappings.map((mapping) => {
                  const colors = CONFIDENCE_COLORS[mapping.confidence];
                  const isActive = activeLabels.includes(mapping.label);
                  return (
                    <TableRow
                      key={`${mapping.label}:${mapping.original}`}
                      className={`transition-colors duration-300 ${
                        isActive ? "bg-amber-50/80" : ""
                      }`}
                    >
                      <TableCell className="py-2">
                        <code
                          className={`rounded-sm border px-1.5 py-0.5 text-xs transition-all duration-300 ${colors.bg} ${colors.text} ${colors.border} ${
                            isActive ? "ring-1 ring-amber-500 shadow-sm shadow-amber-200" : ""
                          }`}
                        >
                          {mapping.label}
                        </code>
                      </TableCell>
                      <TableCell className="break-all py-2 font-mono text-xs text-muted-foreground">
                        {mapping.original}
                      </TableCell>
                      <TableCell className="py-2">
                        <Badge
                          variant="secondary"
                          className={`px-1.5 py-0 text-[10px] ${colors.badge}`}
                        >
                          {mapping.confidence}
                        </Badge>
                      </TableCell>
                      <TableCell className="py-2 text-xs text-muted-foreground">
                        {mapping.reason}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </section>
      </main>
    </div>
  );
}
