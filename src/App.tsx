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
const ANIMATION_TOTAL_MS = 4600;

interface OutputFrame {
  text: string;
  activeLabels: string[];
  appliedLabels: string[];
  scanStartLine: number | null;
  scanEndLine: number | null;
}

function replaceEverywhere(text: string, original: string, replacement: string): string {
  if (!original) return text;
  return text.split(original).join(replacement);
}

function lineIndexAtOffset(text: string, offset: number): number {
  if (offset <= 0) return 0;
  return text.slice(0, offset).split(/\r?\n/).length - 1;
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
    <pre className="font-mono text-[13px] leading-relaxed whitespace-pre-wrap break-all m-0">
      {lines.map((line, index) => {
        const isScanning =
          scanStartLine !== null &&
          scanEndLine !== null &&
          index >= scanStartLine &&
          index <= scanEndLine;

        return (
          <span
            key={index}
            className={`relative block rounded-sm px-1 transition-colors duration-300 ${
              isScanning ? "bg-amber-50/80" : ""
            }`}
          >
            {isScanning && (
              <span className="pointer-events-none absolute inset-0 rounded-sm bg-gradient-to-r from-transparent via-amber-300/35 to-transparent" />
            )}
            <span className="relative">
              {renderHighlightedFragments(line, mappings, activeLabels, `line-${index}`)}
            </span>
            {index < lines.length - 1 ? "\n" : ""}
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

function buildOutputFrames(input: string, result: MaskResult): OutputFrame[] {
  const originalText = buildOutputBody(input);
  const finalText = buildOutputBody(result.masked);
  const originalLines = originalText.split(/\r?\n/);
  const indexedMappings = result.mappingTable
    .map((mapping, order) => ({
      mapping,
      order,
      firstIndex: originalText.indexOf(mapping.original),
      lineIndex:
        originalText.indexOf(mapping.original) === -1
          ? Number.MAX_SAFE_INTEGER
          : lineIndexAtOffset(originalText, originalText.indexOf(mapping.original)),
    }))
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
  const frames: OutputFrame[] = [];

  let currentText = originalText;
  const appliedLabels = new Set<string>();
  const scanRanges = buildScanRanges(originalLines.length, MAX_SCAN_STEPS);

  for (const range of scanRanges) {
    const batchLabels: string[] = [];

    for (const entry of indexedMappings) {
      if (entry.lineIndex < range.start || entry.lineIndex > range.end) continue;
      if (appliedLabels.has(entry.mapping.label)) continue;

      const nextText = replaceEverywhere(
        currentText,
        entry.mapping.original,
        entry.mapping.label
      );
      if (nextText === currentText) continue;

      currentText = nextText;
      appliedLabels.add(entry.mapping.label);
      batchLabels.push(entry.mapping.label);
    }

    frames.push({
      text: currentText,
      activeLabels: batchLabels,
      appliedLabels: [...appliedLabels],
      scanStartLine: range.start,
      scanEndLine: range.end,
    });
  }

  if (frames.length === 0 || frames[frames.length - 1]?.text !== finalText) {
    frames.push({
      text: finalText,
      activeLabels: [],
      appliedLabels: result.mappingTable.map((mapping) => mapping.label),
      scanStartLine: null,
      scanEndLine: null,
    });
  } else if (frames.length > 1) {
    frames.push({
      text: finalText,
      activeLabels: [],
      appliedLabels: result.mappingTable.map((mapping) => mapping.label),
      scanStartLine: null,
      scanEndLine: null,
    });
  }

  return frames;
}

export default function App() {
  const [sourceType, setSourceType] = useState<SourceType>("env");
  const [input, setInput] = useState(SAMPLES.env);
  const [result, setResult] = useState<MaskResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [displayText, setDisplayText] = useState(buildOutputBody(SAMPLES.env));
  const [activeLabels, setActiveLabels] = useState<string[]>([]);
  const [appliedLabels, setAppliedLabels] = useState<string[]>([]);
  const [scanStartLine, setScanStartLine] = useState<number | null>(0);
  const [scanEndLine, setScanEndLine] = useState<number | null>(0);
  const animationTimers = useRef<number[]>([]);

  const primeOutput = (nextInput: string) => {
    setResult(null);
    setDisplayText(buildOutputBody(nextInput));
    setActiveLabels([]);
    setAppliedLabels([]);
    setScanStartLine(nextInput.trim() ? 0 : null);
    setScanEndLine(nextInput.trim() ? 0 : null);
    setCaptureReady(!nextInput.trim());
  };

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (!input.trim()) {
        setResult(null);
        return;
      }

      try {
        setResult(maskOutput(input, sourceType, DEFAULT_MASK_OPTIONS));
      } catch {
        setResult(null);
      }
    }, 180);

    return () => window.clearTimeout(timer);
  }, [input, sourceType]);

  useEffect(() => {
    animationTimers.current.forEach((timer) => window.clearTimeout(timer));
    animationTimers.current = [];

    if (!result) {
      return;
    }

    const frames = buildOutputFrames(input, result);
    const intervalMs = Math.max(
      260,
      Math.min(420, Math.floor(ANIMATION_TOTAL_MS / Math.max(frames.length, 1)))
    );

    setCaptureReady(frames.length === 0);

    const applyFrame = (frame: OutputFrame) => {
      setDisplayText(frame.text);
      setActiveLabels(frame.activeLabels);
      setAppliedLabels(frame.appliedLabels);
      setScanStartLine(frame.scanStartLine);
      setScanEndLine(frame.scanEndLine);
    };

    frames.forEach((frame, index) => {
      const timeoutId = window.setTimeout(() => {
        applyFrame(frame);

        if (index === frames.length - 1) {
          setCaptureReady(true);
        }
      }, 320 + intervalMs * index);

      animationTimers.current.push(timeoutId);
    });

    return () => {
      animationTimers.current.forEach((timer) => window.clearTimeout(timer));
      animationTimers.current = [];
    };
  }, [input, result]);

  const handleCopy = async () => {
    if (!result) return;
    await navigator.clipboard.writeText(buildOutputBody(result.masked));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  };

  const loadSource = (nextSource: SourceType) => {
    setSourceType(nextSource);
    const nextInput = SAMPLES[nextSource];
    setInput(nextInput);
    primeOutput(nextInput);
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
                const nextInput = event.target.value;
                setInput(nextInput);
                primeOutput(nextInput);
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
                  mappings={result?.mappingTable ?? []}
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

        {result && result.mappingTable.length > 0 && (
          <section className="mt-5 rounded-2xl border border-border bg-card p-4">
            <div className="overflow-x-auto">
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
                  {result.mappingTable
                    .filter((mapping) => appliedLabels.includes(mapping.label))
                    .map((mapping) => {
                    const colors = CONFIDENCE_COLORS[mapping.confidence];
                    const isActive = activeLabels.includes(mapping.label);
                    const isApplied = appliedLabels.includes(mapping.label);
                    return (
                      <TableRow
                        key={`${mapping.label}:${mapping.original}`}
                        className={`transition-colors duration-300 ${
                          isActive
                            ? "bg-amber-50/80"
                            : isApplied
                              ? "bg-emerald-50/40"
                              : ""
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
        )}
      </main>
    </div>
  );
}
