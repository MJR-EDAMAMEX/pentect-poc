import { useState, useEffect, useRef, useCallback, Fragment } from "react";
import {
  maskOutput,
  DEFAULT_MASK_OPTIONS,
  type MaskResult,
  type Mapping,
  type MaskOptions,
  type SourceType,
} from "./lib/pripen";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Copy, Check, ChevronDown, ChevronUp } from "lucide-react";

const SAMPLES: { label: string; source: SourceType; text: string }[] = [
  {
    label: "ipconfig",
    source: "generic",
    text: `Windows IP Configuration

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : corp.example.local
   IPv4 Address. . . . . . . . . . . : 192.168.1.105
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1

Ethernet adapter VPN:

   Connection-specific DNS Suffix  . : vpn.example.local
   IPv4 Address. . . . . . . . . . . : 10.8.0.42
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.8.0.1

Wireless LAN adapter Wi-Fi:

   IPv4 Address. . . . . . . . . . . : 172.16.0.88
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 172.16.0.1
   IPv6 Address. . . . . . . . . . . : fe80::1a2b:3c4d:5e6f:7890`,
  },
  {
    label: "Nmap",
    source: "nmap",
    text: `Nmap scan report for db-internal-01 (10.0.1.5)
Host is up (0.0012s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9
3306/tcp  open  mysql   MySQL 8.0.32
33060/tcp open  mysqlx  MySQL X Protocol

Nmap scan report for 10.0.1.1
Host is up (0.0008s latency).

PORT    STATE SERVICE
22/tcp  open  ssh
443/tcp open  https
389/tcp open  ldap

Nmap scan report for 10.0.2.15
Host is up (0.0021s latency).

PORT     STATE SERVICE
8080/tcp open  http-proxy`,
  },
];

const CONFIDENCE_COLORS: Record<
  string,
  { bg: string; text: string; border: string; badge: string }
> = {
  HIGH: {
    bg: "bg-emerald-100 dark:bg-emerald-900/40",
    text: "text-emerald-800 dark:text-emerald-200",
    border: "border-emerald-300 dark:border-emerald-700",
    badge: "bg-emerald-600 text-white",
  },
  LIKELY: {
    bg: "bg-amber-100 dark:bg-amber-900/40",
    text: "text-amber-800 dark:text-amber-200",
    border: "border-amber-300 dark:border-amber-700",
    badge: "bg-amber-500 text-white",
  },
  MAYBE: {
    bg: "bg-orange-100 dark:bg-orange-900/40",
    text: "text-orange-800 dark:text-orange-200",
    border: "border-orange-300 dark:border-orange-700",
    badge: "bg-orange-500 text-white",
  },
  UNKNOWN: {
    bg: "bg-zinc-100 dark:bg-zinc-800",
    text: "text-zinc-600 dark:text-zinc-300",
    border: "border-zinc-300 dark:border-zinc-600",
    badge: "bg-zinc-500 text-white",
  },
};

const OPTION_LABELS: { key: keyof MaskOptions; label: string }[] = [
  { key: "maskIPs", label: "IPアドレス" },
  { key: "maskPorts", label: "ポート番号" },
  { key: "maskHostnames", label: "ホスト名" },
  { key: "maskVersions", label: "バージョン" },
];

function getConfidenceForToken(
  token: string,
  mappings: Mapping[]
): string | null {
  const mapping = mappings.find((m) => m.label === token);
  return mapping?.confidence ?? null;
}

function HighlightedOutput({
  text,
  mappings,
}: {
  text: string;
  mappings: Mapping[];
}) {
  const tokenRegex = /<<.*?>>/g;
  const parts: { text: string; isToken: boolean }[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = tokenRegex.exec(text)) !== null) {
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
      {parts.map((part, i) => {
        if (!part.isToken) return <Fragment key={i}>{part.text}</Fragment>;

        const confidence = getConfidenceForToken(part.text, mappings);
        const colors = confidence
          ? CONFIDENCE_COLORS[confidence]
          : CONFIDENCE_COLORS.UNKNOWN;
        const mapping = mappings.find((m) => m.label === part.text);

        return (
          <TooltipProvider key={i} delayDuration={200}>
            <Tooltip>
              <TooltipTrigger asChild>
                <span
                  className={`inline px-1 py-0.5 rounded-sm font-semibold border ${colors.bg} ${colors.text} ${colors.border} cursor-help`}
                >
                  {part.text}
                </span>
              </TooltipTrigger>
              {mapping && (
                <TooltipContent side="top" className="max-w-xs">
                  <p className="font-mono text-xs">{mapping.original}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    {mapping.reason}
                  </p>
                </TooltipContent>
              )}
            </Tooltip>
          </TooltipProvider>
        );
      })}
    </pre>
  );
}

function MappingTable({ mappings }: { mappings: Mapping[] }) {
  const [expanded, setExpanded] = useState(true);

  return (
    <div className="border border-border rounded-md overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-3 bg-muted/50 hover:bg-muted transition-colors"
      >
        <span className="text-sm font-medium tracking-tight">
          マッピング表
        </span>
        {expanded ? (
          <ChevronUp className="h-4 w-4 text-muted-foreground" />
        ) : (
          <ChevronDown className="h-4 w-4 text-muted-foreground" />
        )}
      </button>
      {expanded && (
        <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="bg-muted/30">
              <TableHead className="w-[180px] text-xs">ラベル</TableHead>
              <TableHead className="text-xs">元の値</TableHead>
              <TableHead className="w-[100px] text-xs">確信度</TableHead>
              <TableHead className="text-xs">推定理由</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {mappings.map((m, i) => {
              const colors = CONFIDENCE_COLORS[m.confidence];
              return (
                <TableRow key={i} className="font-mono text-xs">
                  <TableCell className="py-2">
                    <code
                      className={`px-1.5 py-0.5 rounded-sm ${colors.bg} ${colors.text} ${colors.border} border`}
                    >
                      {m.label}
                    </code>
                  </TableCell>
                  <TableCell className="py-2 text-muted-foreground">
                    {m.original}
                  </TableCell>
                  <TableCell className="py-2">
                    <Badge
                      variant="secondary"
                      className={`text-[10px] px-1.5 py-0 ${colors.badge}`}
                    >
                      {m.confidence}
                    </Badge>
                  </TableCell>
                  <TableCell className="py-2 text-muted-foreground font-sans text-xs">
                    {m.reason}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [input, setInput] = useState(SAMPLES[0].text);
  const [result, setResult] = useState<MaskResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [sourceType, setSourceType] = useState<SourceType>("generic");
  const [options, setOptions] = useState<MaskOptions>({
    ...DEFAULT_MASK_OPTIONS,
  });
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  const runMask = useCallback(
    (text: string) => {
      if (!text.trim()) {
        setResult(null);
        return;
      }
      try {
        setResult(maskOutput(text, sourceType, options));
      } catch {
        setResult(null);
      }
    },
    [sourceType, options]
  );

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => runMask(input), 200);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [input, runMask]);

  const handleCopy = async () => {
    if (!result) return;
    await navigator.clipboard.writeText(result.masked);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const toggleOption = (key: keyof MaskOptions) => {
    setOptions((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <div className="min-h-screen bg-background">
      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-5">
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 mb-4">
          <div className="flex items-center gap-1.5 mr-2">
            <span className="text-xs text-muted-foreground">解析:</span>
            {([
              { value: "generic" as const, label: "汎用" },
              { value: "nmap" as const, label: "Nmap" },
            ]).map((t) => (
              <button
                key={t.value}
                onClick={() => setSourceType(t.value)}
                className={`text-xs px-2 py-0.5 rounded border transition-colors ${
                  sourceType === t.value
                    ? "bg-foreground text-background border-foreground"
                    : "bg-transparent text-muted-foreground border-border hover:border-foreground/50"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
          {OPTION_LABELS.map(({ key, label }) => (
            <div key={key} className="flex items-center gap-2">
              <Switch
                id={key}
                checked={options[key]}
                onCheckedChange={() => toggleOption(key)}
                className="scale-75"
              />
              <Label htmlFor={key} className="text-xs cursor-pointer">
                {label}
              </Label>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <label className="text-sm font-medium tracking-tight">入力</label>
              <span className="text-[11px] text-muted-foreground">例:</span>
              {SAMPLES.map((s) => (
                <button
                  key={s.label}
                  onClick={() => {
                    setInput(s.text);
                    setSourceType(s.source);
                  }}
                  className="text-[11px] px-1.5 py-0.5 rounded border border-border text-muted-foreground hover:border-foreground/50 hover:text-foreground transition-colors"
                >
                  {s.label}
                </button>
              ))}
            </div>
            <Textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="ペンテスト出力やネットワーク情報を貼り付け..."
              className="font-mono text-[13px] leading-relaxed min-h-[200px] sm:min-h-[420px] resize-none flex-1 bg-muted/30"
              spellCheck={false}
            />
          </div>

          <div className="flex flex-col gap-2">
            <label className="text-sm font-medium tracking-tight">
              出力
            </label>
            <div className="relative border border-input rounded-md bg-muted/30 px-3 py-2 min-h-[200px] sm:min-h-[420px] flex-1 overflow-auto">
              <Button
                variant="ghost"
                size="sm"
                onClick={handleCopy}
                disabled={!result}
                className="absolute top-1.5 right-1.5 h-7 px-2 text-xs gap-1.5 z-10"
              >
                {copied ? (
                  <Check className="h-3.5 w-3.5" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
                {copied ? "コピー済" : "コピー"}
              </Button>
              {result ? (
                <HighlightedOutput
                  text={result.masked}
                  mappings={result.mappingTable}
                />
              ) : (
                <p className="text-sm text-muted-foreground italic">
                  変換結果がここに表示されます...
                </p>
              )}
            </div>
          </div>
        </div>

        {result && result.mappingTable.length > 0 && (
          <MappingTable mappings={result.mappingTable} />
        )}

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <span className="text-xs text-muted-foreground">確信度:</span>
          {(["HIGH", "LIKELY", "MAYBE", "UNKNOWN"] as const).map((level) => {
            const c = CONFIDENCE_COLORS[level];
            return (
              <span
                key={level}
                className={`text-[11px] px-2 py-0.5 rounded-sm border ${c.bg} ${c.text} ${c.border}`}
              >
                {level}
              </span>
            );
          })}
        </div>

        <section className="mt-8 border-t border-border pt-6 text-xs text-muted-foreground space-y-3 max-w-2xl">
          <h2 className="text-sm font-medium text-foreground">仕組み</h2>
          <p>
            PriPenはペンテスト出力やネットワーク情報に含まれる機密情報を、
            <code className="text-foreground">{"<<IP_DB_1>>"}</code>や
            <code className="text-foreground">{"<<FQDN_1>>"}</code>
            のようなセマンティックラベルに変換します。
            同じ値には常に同じラベルが割り当てられるため、
            元データの構造を保ったままIPアドレス・ホスト名・ドメイン・ポート番号・バージョン文字列を隠蔽できます。
          </p>
          <p>
            汎用モードは正規表現ベースでIPv4/IPv6アドレスやFQDNを検出します。
            ツール固有のパーサーを選択すると、構造解析によりポートの役割推定や確信度の判定も行います。
          </p>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
            <dt className="font-medium text-foreground">HIGH</dt>
            <dd>そのロール以外ではほぼ使われない（例: ポート22 = SSH）</dd>
            <dt className="font-medium text-foreground">LIKELY</dt>
            <dd>最有力だが、代替用途もあり得る</dd>
            <dt className="font-medium text-foreground">MAYBE</dt>
            <dd>複数候補があり断定できない</dd>
            <dt className="font-medium text-foreground">UNKNOWN</dt>
            <dd>既知のシグネチャなし</dd>
          </dl>
        </section>
      </main>
    </div>
  );
}
