export type Confidence = "HIGH" | "LIKELY" | "MAYBE" | "UNKNOWN";

export type SourceType = "env" | "nmap" | "har";

export interface MaskOptions {
  includeSummary: boolean;
}

export const DEFAULT_MASK_OPTIONS: MaskOptions = {
  includeSummary: true,
};

export interface Mapping {
  label: string;
  original: string;
  confidence: Confidence;
  reason: string;
}

export interface SummaryItem {
  label: string;
  value: string;
}

export interface MaskResult {
  masked: string;
  aiBundle: string;
  mappingTable: Mapping[];
  summary: SummaryItem[];
  sourceType: SourceType;
}

interface SummaryCounts {
  source: SourceType;
  lines: number;
  chars: number;
  chunks: number;
  largeArtifactMode: "ON" | "OFF";
  endpoints: number;
  auth: number;
  authReuse: number;
  contacts: number;
  internalEndpoints: number;
  publicEndpoints: number;
  authCategories: number;
  contactCategories: number;
  extras?: SummaryItem[];
}

const CHUNK_MAX_LINES = 48;
const LARGE_ARTIFACT_LINE_THRESHOLD = 48;
const LARGE_ARTIFACT_CHAR_THRESHOLD = 4096;

const SENSITIVE_KEY_RE =
  /(secret|token|api[_-]?key|password|passwd|pwd|cookie|session|auth|bearer|private[_-]?key|client[_-]?secret|access[_-]?key)/i;
const URL_RE = /https?:\/\/[^\s"'<>\\]+/g;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const EMAIL_SINGLE_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
const IPV4_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const FQDN_RE =
  /\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b/g;
const FQDN_SINGLE_RE =
  /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;
const AUTH_VALUE_RE = /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}\b/g;
const HAR_HEADER_RE =
  /^(authorization|cookie|set-cookie|x-api-key|proxy-authorization|x-auth-token)$/i;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function stripQuotes(value: string): string {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function wrapLike(originalValue: string, label: string): string {
  const trimmed = originalValue.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return `${trimmed[0]}${label}${trimmed[0]}`;
  }
  return label;
}

function isValidIpv4(ip: string): boolean {
  return ip.split(".").every((octet) => {
    const num = Number.parseInt(octet, 10);
    return Number.isInteger(num) && num >= 0 && num <= 255;
  });
}

function isPrivateIpv4(ip: string): boolean {
  if (!isValidIpv4(ip)) return false;
  const [a, b] = ip.split(".").map((part) => Number.parseInt(part, 10));
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 127
  );
}

function isInternalHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return (
    normalized.endsWith(".internal") ||
    normalized.endsWith(".local") ||
    normalized.endsWith(".corp") ||
    normalized.includes("internal") ||
    normalized.includes("corp") ||
    normalized.includes("vpn")
  );
}

function looksSensitiveValue(value: string): boolean {
  const trimmed = stripQuotes(value);
  if (!trimmed) return false;
  if (/^AKIA[0-9A-Z]{16}$/.test(trimmed)) return true;
  if (/^gh[pousr]_[A-Za-z0-9]{20,}$/.test(trimmed)) return true;
  if (/^AIza[0-9A-Za-z_-]{20,}$/.test(trimmed)) return true;
  if (/^eyJ[A-Za-z0-9._-]{16,}$/.test(trimmed)) return true;
  if (/^[A-Za-z0-9+/_=-]{24,}$/.test(trimmed)) return true;
  return false;
}

function buildTopList(counts: Map<string, number>, limit = 3): string {
  const top = [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit);

  if (top.length === 0) return "none";
  return top.map(([label, count]) => `${label}:${count}`).join(", ");
}

function replaceAllSorted(
  text: string,
  replacements: Array<[string, string]>
): string {
  let result = text;
  const sorted = [...replacements].sort((a, b) => b[0].length - a[0].length);
  for (const [needle, label] of sorted) {
    if (!needle) continue;
    result = result.split(needle).join(label);
  }
  return result;
}

function collectMatches(text: string, regex: RegExp): string[] {
  regex.lastIndex = 0;
  const matches = new Set<string>();
  let match: RegExpExecArray | null;
  while ((match = regex.exec(text)) !== null) {
    matches.add(match[0]);
    if (match.index === regex.lastIndex) regex.lastIndex += 1;
  }
  return [...matches];
}

function countLines(text: string): number {
  if (!text) return 0;
  return text.split(/\r?\n/).length;
}

function canonicalEndpointValue(value: string): string {
  const trimmed = stripQuotes(value);
  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      return `${parsed.origin}${parsed.pathname}`;
    } catch {
      return trimmed;
    }
  }
  return trimmed;
}

function classifyEndpointScope(
  value: string
): "internal" | "public" | "none" {
  const trimmed = stripQuotes(value);
  if (!trimmed) return "none";

  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const hostname = new URL(trimmed).hostname;
      if (isValidIpv4(hostname)) {
        return isPrivateIpv4(hostname) ? "internal" : "public";
      }
      return isInternalHost(hostname) ? "internal" : "public";
    } catch {
      return "none";
    }
  }

  if (isValidIpv4(trimmed)) {
    return isPrivateIpv4(trimmed) ? "internal" : "public";
  }

  if (FQDN_SINGLE_RE.test(trimmed) && !EMAIL_SINGLE_RE.test(trimmed)) {
    return isInternalHost(trimmed) ? "internal" : "public";
  }

  return "none";
}

function trackEndpoint(
  value: string,
  allEndpoints: Set<string>,
  internalEndpoints: Set<string>,
  publicEndpoints: Set<string>
): void {
  const scope = classifyEndpointScope(value);
  if (scope === "none") return;

  const canonical = canonicalEndpointValue(value);
  allEndpoints.add(canonical);
  if (scope === "internal") {
    internalEndpoints.add(canonical);
  } else {
    publicEndpoints.add(canonical);
  }
}

function classifyAuthCategory(text: string): string | null {
  const normalized = text.toLowerCase();
  if (/cookie|session/.test(normalized)) return "session";
  if (/password|passwd|pwd/.test(normalized)) return "password";
  if (/bearer|token|auth/.test(normalized)) return "token";
  if (/private[_-]?key/.test(normalized)) return "private_key";
  if (/api[_-]?key|access[_-]?key|secret|client[_-]?secret/.test(normalized)) {
    return "key";
  }
  return null;
}

function summarizeCounts(counts: SummaryCounts): SummaryItem[] {
  const items: SummaryItem[] = [
    { label: "SOURCE_TYPE", value: counts.source.toUpperCase() },
    { label: "SUMMARY_LARGE_ARTIFACT_MODE", value: counts.largeArtifactMode },
    { label: "SUMMARY_LINES", value: String(counts.lines) },
    { label: "SUMMARY_CHARS", value: String(counts.chars) },
    { label: "SUMMARY_CHUNKS", value: String(counts.chunks) },
    { label: "SUMMARY_ENDPOINTS", value: String(counts.endpoints) },
    {
      label: "SUMMARY_INTERNAL_ENDPOINTS",
      value: String(counts.internalEndpoints),
    },
    {
      label: "SUMMARY_PUBLIC_ENDPOINTS",
      value: String(counts.publicEndpoints),
    },
    { label: "SUMMARY_AUTH", value: String(counts.auth) },
    { label: "SUMMARY_AUTH_REUSE", value: String(counts.authReuse) },
    {
      label: "SUMMARY_AUTH_CATEGORIES",
      value: String(counts.authCategories),
    },
    { label: "SUMMARY_CONTACTS", value: String(counts.contacts) },
    {
      label: "SUMMARY_CONTACT_CATEGORIES",
      value: String(counts.contactCategories),
    },
  ];

  if (counts.extras?.length) {
    items.push(...counts.extras);
  }

  return items;
}

function splitStreamingChunks(text: string, maxLines = CHUNK_MAX_LINES): string[] {
  if (!text) return [""];

  const lines = text.split(/\r?\n/);
  const chunks: string[] = [];
  let current: string[] = [];
  let fencedBlockDepth = 0;

  for (const line of lines) {
    if (line.startsWith("-----BEGIN ") && line.endsWith("-----")) {
      fencedBlockDepth += 1;
    }

    current.push(line);

    if (line.startsWith("-----END ") && line.endsWith("-----")) {
      fencedBlockDepth = Math.max(0, fencedBlockDepth - 1);
    }

    if (current.length >= maxLines && fencedBlockDepth === 0) {
      chunks.push(current.join("\n"));
      current = [];
    }
  }

  if (current.length > 0) {
    chunks.push(current.join("\n"));
  }

  return chunks.length > 0 ? chunks : [""];
}


function buildAiBundle(
  masked: string,
  summary: SummaryItem[]
): string {
  const body = masked;
  const chunks = splitStreamingChunks(body, CHUNK_MAX_LINES);
  const lines = ["PENTECT_BUNDLE_V1", "[MASKED_BODY]"];

  chunks.forEach((chunk, index) => {
    lines.push(`CHUNK ${index + 1}/${chunks.length}`);
    if (chunk) {
      lines.push(chunk);
    }
  });

  if (summary.length > 0) {
    lines.push("[AGGREGATE_SUMMARY]");
    for (const item of summary) {
      lines.push(`${item.label}=${item.value}`);
    }
  }

  return lines.join("\n");
}

class LabelBook {
  private readonly valueToLabel = new Map<string, string>();
  private nextValue = 1;

  readonly mappings: Mapping[] = [];

  assignValue(original: string, confidence: Confidence, reason: string): string {
    const existing = this.valueToLabel.get(original);
    if (existing) return existing;

    const label = `<<VALUE_${String(this.nextValue).padStart(3, "0")}>>`;
    this.nextValue += 1;
    this.valueToLabel.set(original, label);
    this.mappings.push({ label, original, confidence, reason });
    return label;
  }
}

function applyGenericMasks(text: string, book: LabelBook): string {
  let result = text;

  const authValues = collectMatches(result, AUTH_VALUE_RE);
  result = replaceAllSorted(
    result,
    authValues.map((value) => [
      value,
      book.assignValue(value, "HIGH", "authorization-like value"),
    ])
  );

  const urls = collectMatches(result, URL_RE);
  result = replaceAllSorted(
    result,
    urls.map((value) => [value, book.assignValue(value, "LIKELY", "URL")])
  );

  const emails = collectMatches(result, EMAIL_RE);
  result = replaceAllSorted(
    result,
    emails.map((value) => [
      value,
      book.assignValue(value, "HIGH", "email address"),
    ])
  );

  const ipv4s = collectMatches(result, IPV4_RE).filter(isValidIpv4);
  result = replaceAllSorted(
    result,
    ipv4s.map((value) => [
      value,
      book.assignValue(
        value,
        isPrivateIpv4(value) ? "HIGH" : "LIKELY",
        "IPv4 address"
      ),
    ])
  );

  const domains = collectMatches(result, FQDN_RE).filter((value) => {
    return !value.startsWith("<<") && !value.includes("@");
  });
  result = replaceAllSorted(
    result,
    domains.map((value) => [
      value,
      book.assignValue(
        value,
        isInternalHost(value) ? "LIKELY" : "MAYBE",
        "domain or FQDN"
      ),
    ])
  );

  return result;
}

function replaceCaseSensitiveWord(
  text: string,
  original: string,
  replacement: string
): string {
  return text.replace(new RegExp(escapeRegExp(original), "g"), replacement);
}

function finalizeResult(
  masked: string,
  book: LabelBook,
  summary: SummaryItem[],
  sourceType: SourceType
): MaskResult {
  return {
    masked,
    aiBundle: buildAiBundle(masked, summary),
    mappingTable: book.mappings,
    summary,
    sourceType,
  };
}

function maskEnv(input: string, options: MaskOptions): MaskResult {
  const book = new LabelBook();
  const lines = input.split(/\r?\n/);
  const secretReuse = new Map<string, number>();
  const endpointValues = new Set<string>();
  const internalEndpointValues = new Set<string>();
  const publicEndpointValues = new Set<string>();
  const contactValues = new Set<string>();
  const authCategories = new Set<string>();
  let totalEntries = 0;
  let sensitiveEntries = 0;

  const maskedLines = lines.map((line) => {
    const match = line.match(
      /^(\s*export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/
    );
    if (!match) return line;

    totalEntries += 1;
    const exportPrefix = match[1] ?? "";
    const key = match[2];
    const rawValue = match[3];
    const normalizedValue = stripQuotes(rawValue);
    const keySensitive = SENSITIVE_KEY_RE.test(key);
    const valueSensitive = looksSensitiveValue(normalizedValue);
    const authCategory = classifyAuthCategory(key);

    if (EMAIL_SINGLE_RE.test(normalizedValue)) {
      contactValues.add(normalizedValue);
    } else {
      trackEndpoint(
        normalizedValue,
        endpointValues,
        internalEndpointValues,
        publicEndpointValues
      );
    }

    if (keySensitive || valueSensitive) {
      sensitiveEntries += 1;
      secretReuse.set(
        normalizedValue,
        (secretReuse.get(normalizedValue) ?? 0) + 1
      );
      if (authCategory) {
        authCategories.add(authCategory);
      }
      const keyText = key;
      const valueLabel = book.assignValue(
        normalizedValue,
        "HIGH",
        `env value for ${key}`
      );
      return `${exportPrefix}${keyText}=${wrapLike(rawValue, valueLabel)}`;
    }

    const maskedValue = applyGenericMasks(rawValue, book);
    return `${exportPrefix}${key}=${maskedValue}`;
  });

  const masked = maskedLines.join("\n");
  const chunkCount = splitStreamingChunks(
    masked,
    CHUNK_MAX_LINES
  ).length;
  const reusedSecrets = [...secretReuse.values()].filter((count) => count > 1)
    .length;
  const summary = options.includeSummary
    ? summarizeCounts({
        source: "env",
        lines: countLines(input),
        chars: input.length,
        chunks: chunkCount,
        largeArtifactMode:
          countLines(input) > LARGE_ARTIFACT_LINE_THRESHOLD ||
          input.length > LARGE_ARTIFACT_CHAR_THRESHOLD
            ? "ON"
            : "OFF",
        endpoints: endpointValues.size,
        auth: secretReuse.size,
        authReuse: reusedSecrets,
        contacts: contactValues.size,
        internalEndpoints: internalEndpointValues.size,
        publicEndpoints: publicEndpointValues.size,
        authCategories: authCategories.size,
        contactCategories: contactValues.size > 0 ? 1 : 0,
        extras: [
          { label: "SUMMARY_ENTRIES", value: String(totalEntries) },
          {
            label: "SUMMARY_SENSITIVE_ENTRIES",
            value: String(sensitiveEntries),
          },
        ],
      })
    : [];

  return finalizeResult(masked, book, summary, "env");
}

function maskNmap(input: string, options: MaskOptions): MaskResult {
  const book = new LabelBook();
  const services = new Map<string, number>();
  const hostValues = new Set<string>();
  const internalEndpointValues = new Set<string>();
  const publicEndpointValues = new Set<string>();
  let openPorts = 0;

  const maskedLines = input.split(/\r?\n/).map((line) => {
    const hostWithName = line.match(
      /^(\s*Nmap scan report for\s+)(\S+)\s+\(([0-9a-fA-F:.%]+)\)(.*)$/
    );
    if (hostWithName) {
      const hostname = hostWithName[2];
      const ip = hostWithName[3];
      hostValues.add(hostname);
      if (isPrivateIpv4(ip) || isInternalHost(hostname)) {
        internalEndpointValues.add(hostname);
      } else {
        publicEndpointValues.add(hostname);
      }
      const hostLabel = book.assignValue(hostname, "LIKELY", "nmap hostname");
      const ipLabel = book.assignValue(ip, "HIGH", "nmap target IP");
      return `${hostWithName[1]}${hostLabel} (${ipLabel})${hostWithName[4]}`;
    }

    const hostIpOnly = line.match(
      /^(\s*Nmap scan report for\s+)([0-9a-fA-F:.%]+)(.*)$/
    );
    if (hostIpOnly) {
      const ip = hostIpOnly[2];
      hostValues.add(ip);
      if (isPrivateIpv4(ip)) {
        internalEndpointValues.add(ip);
      } else {
        publicEndpointValues.add(ip);
      }
      const ipLabel = book.assignValue(ip, "HIGH", "nmap target IP");
      return `${hostIpOnly[1]}${ipLabel}${hostIpOnly[3]}`;
    }

    const portLine = line.match(
      /^(\s*)(\d+)\/(tcp|udp)(\s+)(open|closed|filtered)(\s+)(\S+)(.*)$/
    );
    if (portLine) {
      const port = portLine[2];
      const state = portLine[5];
      const service = portLine[7];
      const rest = portLine[8];

      if (state === "open") {
        openPorts += 1;
        services.set(service, (services.get(service) ?? 0) + 1);
      }

      const portLabel = book.assignValue(port, "LIKELY", "nmap port number");
      let suffix = rest;
      if (rest.trim()) {
        const versionLabel = book.assignValue(
          rest.trim(),
          "MAYBE",
          "service banner or version"
        );
        suffix = ` ${versionLabel}`;
      }

      return `${portLine[1]}${portLabel}/${portLine[3]}${portLine[4]}${state}${portLine[6]}${service}${suffix}`;
    }

    return line;
  });

  const masked = applyGenericMasks(maskedLines.join("\n"), book);
  const chunkCount = splitStreamingChunks(
    masked,
    CHUNK_MAX_LINES
  ).length;
  const summary = options.includeSummary
    ? summarizeCounts({
        source: "nmap",
        lines: countLines(input),
        chars: input.length,
        chunks: chunkCount,
        largeArtifactMode:
          countLines(input) > LARGE_ARTIFACT_LINE_THRESHOLD ||
          input.length > LARGE_ARTIFACT_CHAR_THRESHOLD
            ? "ON"
            : "OFF",
        endpoints: hostValues.size,
        auth: 0,
        authReuse: 0,
        contacts: 0,
        internalEndpoints: internalEndpointValues.size,
        publicEndpoints: publicEndpointValues.size,
        authCategories: 0,
        contactCategories: 0,
        extras: [
          { label: "SUMMARY_OPEN_PORTS", value: String(openPorts) },
          {
            label: "SUMMARY_SERVICE_TYPES",
            value: String(services.size),
          },
          {
            label: "SUMMARY_TOP_SERVICES",
            value: buildTopList(services),
          },
        ],
      })
    : [];

  return finalizeResult(masked, book, summary, "nmap");
}

function tryGetHarEntries(input: string): Array<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(input) as {
      log?: { entries?: Array<Record<string, unknown>> };
    };
    if (Array.isArray(parsed.log?.entries)) {
      return parsed.log.entries;
    }
  } catch {
    return [];
  }
  return [];
}

function maskHar(input: string, options: MaskOptions): MaskResult {
  const book = new LabelBook();
  const entries = tryGetHarEntries(input);
  const uniqueEndpoints = new Set<string>();
  const internalEndpointValues = new Set<string>();
  const publicEndpointValues = new Set<string>();
  const authReuse = new Map<string, number>();
  const authCategories = new Set<string>();
  const contactValues = new Set(collectMatches(input, EMAIL_RE));
  let text = input;

  for (const entry of entries) {
    const request = entry.request as
      | { url?: string; headers?: Array<{ name?: string; value?: string }> }
      | undefined;
    const response = entry.response as
      | { headers?: Array<{ name?: string; value?: string }> }
      | undefined;

    if (request?.url) {
      const urlLabel = book.assignValue(request.url, "HIGH", "HAR request URL");
      text = replaceCaseSensitiveWord(text, request.url, urlLabel);
      const canonical = canonicalEndpointValue(request.url);
      uniqueEndpoints.add(canonical);
      if (classifyEndpointScope(request.url) === "internal") {
        internalEndpointValues.add(canonical);
      } else if (classifyEndpointScope(request.url) === "public") {
        publicEndpointValues.add(canonical);
      }
    }

    const headerGroups = [request?.headers ?? [], response?.headers ?? []];
    for (const headers of headerGroups) {
      for (const header of headers) {
        const name = header.name ?? "";
        const value = header.value ?? "";
        if (!name || !value) continue;
        if (!HAR_HEADER_RE.test(name)) continue;

        const category = classifyAuthCategory(name);
        if (category) {
          authCategories.add(category);
        }

        const valueLabel = book.assignValue(
          value,
          "HIGH",
          `HAR header value: ${name}`
        );
        authReuse.set(value, (authReuse.get(value) ?? 0) + 1);
        text = replaceCaseSensitiveWord(text, value, valueLabel);

      }
    }
  }

  const masked = applyGenericMasks(text, book);
  const chunkCount = splitStreamingChunks(
    masked,
    CHUNK_MAX_LINES
  ).length;
  const reusedAuth = [...authReuse.values()].filter((count) => count > 1)
    .length;
  const summary = options.includeSummary
    ? summarizeCounts({
        source: "har",
        lines: countLines(input),
        chars: input.length,
        chunks: chunkCount,
        largeArtifactMode:
          countLines(input) > LARGE_ARTIFACT_LINE_THRESHOLD ||
          input.length > LARGE_ARTIFACT_CHAR_THRESHOLD
            ? "ON"
            : "OFF",
        endpoints: uniqueEndpoints.size,
        auth: authReuse.size,
        authReuse: reusedAuth,
        contacts: contactValues.size,
        internalEndpoints: internalEndpointValues.size,
        publicEndpoints: publicEndpointValues.size,
        authCategories: authCategories.size,
        contactCategories: contactValues.size > 0 ? 1 : 0,
        extras: [
          { label: "SUMMARY_ENTRIES", value: String(entries.length) },
        ],
      })
    : [];

  return finalizeResult(masked, book, summary, "har");
}

export function maskOutput(
  input: string,
  sourceType: SourceType,
  options: MaskOptions = DEFAULT_MASK_OPTIONS
): MaskResult {
  switch (sourceType) {
    case "env":
      return maskEnv(input, options);
    case "nmap":
      return maskNmap(input, options);
    case "har":
      return maskHar(input, options);
  }
}
