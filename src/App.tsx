import { useEffect, useState, Fragment } from "react";
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

function tokenRegex(): RegExp {
  return /<<[^>]+>>/g;
}

function getMapping(label: string, mappings: Mapping[]): Mapping | undefined {
  return mappings.find((entry) => entry.label === label);
}

function HighlightedOutput({
  text,
  mappings,
}: {
  text: string;
  mappings: Mapping[];
}) {
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

  return (
    <pre className="font-mono text-[13px] leading-relaxed whitespace-pre-wrap break-all m-0">
      {parts.map((part, index) => {
        if (!part.isToken) return <Fragment key={index}>{part.text}</Fragment>;

        const mapping = getMapping(part.text, mappings);
        const colors = CONFIDENCE_COLORS[mapping?.confidence ?? "UNKNOWN"];

        return (
          <span
            key={index}
            title={mapping ? `${mapping.original} | ${mapping.reason}` : part.text}
            className={`inline px-1 py-0.5 rounded-sm border font-semibold ${colors.bg} ${colors.text} ${colors.border}`}
          >
            {part.text}
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

export default function App() {
  const [sourceType, setSourceType] = useState<SourceType>("env");
  const [input, setInput] = useState(SAMPLES.env);
  const [result, setResult] = useState<MaskResult | null>(null);
  const [copied, setCopied] = useState(false);

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

  const handleCopy = async () => {
    if (!result) return;
    await navigator.clipboard.writeText(buildOutputBody(result.masked));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  };

  const loadSource = (nextSource: SourceType) => {
    setSourceType(nextSource);
    setInput(SAMPLES[nextSource]);
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
              onChange={(event) => setInput(event.target.value)}
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
              {result ? (
                <HighlightedOutput
                  text={buildOutputBody(result.masked)}
                  mappings={result.mappingTable}
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
                  {result.mappingTable.map((mapping) => {
                    const colors = CONFIDENCE_COLORS[mapping.confidence];
                    return (
                      <TableRow key={`${mapping.label}:${mapping.original}`}>
                        <TableCell className="py-2">
                          <code
                            className={`rounded-sm border px-1.5 py-0.5 text-xs ${colors.bg} ${colors.text} ${colors.border}`}
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
