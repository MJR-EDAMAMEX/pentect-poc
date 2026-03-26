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
    bg: "bg-blue-50",
    text: "text-blue-700",
    border: "border-blue-200",
    badge: "bg-blue-600 text-white",
  },
  LIKELY: {
    bg: "bg-slate-50",
    text: "text-slate-600",
    border: "border-slate-200",
    badge: "bg-slate-500 text-white",
  },
  MAYBE: {
    bg: "bg-slate-50",
    text: "text-slate-500",
    border: "border-slate-200",
    badge: "bg-slate-400 text-white",
  },
  UNKNOWN: {
    bg: "bg-gray-50",
    text: "text-gray-500",
    border: "border-gray-200",
    badge: "bg-gray-400 text-white",
  },
};


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
        className={`inline px-1 py-0.5 rounded-sm border font-semibold  ${colors.bg} ${colors.text} ${colors.border} ${
          isActive ? "" : ""
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
}: {
  text: string;
  mappings: Mapping[];
  activeLabels: string[];
  scanStartLine?: number | null;
  scanEndLine?: number | null;
}) {
  const lines = text.split(/\r?\n/);

  return (
    <pre className="m-0 whitespace-pre-wrap break-all font-mono text-[13px] leading-6">
      {lines.map((line, index) => {
        return (
          <span
            key={index}
            className="relative block px-1"
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
  const previousResultRef = useRef<MaskResult | null>(null);
  const previousInputRef = useRef<string | null>(null);
  const previousSourceTypeRef = useRef<SourceType>("env");

  useEffect(() => {
    if (!input.trim()) {
      setResult(null);
      setDisplayText("");
      setActiveLabels([]);
      setTableMappings([]);
      previousResultRef.current = null;
      previousInputRef.current = input;
      previousSourceTypeRef.current = sourceType;
      setCaptureReady(true);
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
      setDisplayText(buildOutputBody(stableResult.masked));
      setActiveLabels(stableResult.mappingTable.map((m) => m.label));
      setTableMappings(stableResult.mappingTable);
      previousResultRef.current = stableResult;
    } catch {
      setResult(null);
      setDisplayText("");
      setActiveLabels([]);
      setTableMappings([]);
      previousResultRef.current = null;
    }

    previousInputRef.current = input;
    previousSourceTypeRef.current = sourceType;
    setCaptureReady(true);
  }, [input, sourceType]);

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
                      className={` ${
                        ""
                      }`}
                    >
                      <TableCell className="py-2">
                        <code
                          className={`rounded-sm border px-1.5 py-0.5 text-xs  ${colors.bg} ${colors.text} ${colors.border} ${
                            isActive ? "" : ""
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
