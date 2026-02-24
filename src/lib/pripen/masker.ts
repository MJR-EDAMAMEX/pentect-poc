import { classifyHost, getPortRole } from "./classifier";
import type {
  HostEntry,
  Mapping,
  MaskResult,
  MaskOptions,
  Confidence,
} from "./types";

interface LabelState {
  ipToLabel: Map<string, string>;
  portToLabel: Map<number, string>;
  stringToLabel: Map<string, string>;
  roleCounts: Map<string, number>;
  portRoleCounts: Map<string, number>;
  strCount: number;
  mappings: Mapping[];
}

function initState(): LabelState {
  return {
    ipToLabel: new Map(),
    portToLabel: new Map(),
    stringToLabel: new Map(),
    roleCounts: new Map(),
    portRoleCounts: new Map(),
    strCount: 0,
    mappings: [],
  };
}

function buildHostLabel(
  role: string,
  confidence: Confidence,
  state: LabelState
): string {
  const key = `${confidence}_${role}`;
  const count = (state.roleCounts.get(key) || 0) + 1;
  state.roleCounts.set(key, count);

  if (role === "UNKNOWN") return `<<IP_${confidence}_${count}>>`;
  return `<<IP_${confidence}_${role}_${count}>>`;
}

function buildPortLabel(port: number, state: LabelState): string {
  if (state.portToLabel.has(port)) return state.portToLabel.get(port)!;

  const portRole = getPortRole(port);
  let label: string;
  if (portRole) {
    label = `<<PORT_${portRole.label}>>`;
  } else {
    const count = (state.portRoleCounts.get("port_unknown") || 0) + 1;
    state.portRoleCounts.set("port_unknown", count);
    label = `<<PORT_${port}>>`;
  }
  state.portToLabel.set(port, label);
  return label;
}

function buildStrayIpLabel(state: LabelState): string {
  const key = "stray_ip";
  const count = (state.roleCounts.get(key) || 0) + 1;
  state.roleCounts.set(key, count);
  return `<<IP_MAYBE_${count}>>`;
}

function buildStrLabel(state: LabelState): string {
  state.strCount++;
  return `<<STR_${state.strCount}>>`;
}

function assignHostLabels(
  hosts: HostEntry[],
  state: LabelState,
  opts: MaskOptions
): void {
  for (const host of hosts) {
    if (opts.maskIPs && !state.ipToLabel.has(host.ip)) {
      const classification = classifyHost(host);
      const label = buildHostLabel(
        classification.role,
        classification.confidence,
        state
      );
      state.ipToLabel.set(host.ip, label);

      const originalParts = [host.ip];
      if (host.hostname) originalParts.push(host.hostname);

      state.mappings.push({
        label,
        original: originalParts.join(" / "),
        confidence: classification.confidence,
        reason: classification.reason,
      });
    }

    if (
      opts.maskHostnames &&
      host.hostname &&
      !state.stringToLabel.has(host.hostname)
    ) {
      const strLabel = buildStrLabel(state);
      state.stringToLabel.set(host.hostname, strLabel);
      const classification = classifyHost(host);
      state.mappings.push({
        label: strLabel,
        original: host.hostname,
        confidence: classification.confidence,
        reason: "hostname",
      });
    }

    for (const p of host.ports) {
      if (opts.maskPorts && !state.portToLabel.has(p.port)) {
        const portLabel = buildPortLabel(p.port, state);
        const portRole = getPortRole(p.port);
        state.mappings.push({
          label: portLabel,
          original: String(p.port),
          confidence: portRole?.confidence || "UNKNOWN",
          reason: `port ${p.port} → ${p.service}`,
        });
      }

      if (
        opts.maskVersions &&
        p.version &&
        !state.stringToLabel.has(p.version)
      ) {
        const strLabel = buildStrLabel(state);
        state.stringToLabel.set(p.version, strLabel);
        state.mappings.push({
          label: strLabel,
          original: p.version,
          confidence: "HIGH",
          reason: "version string",
        });
      }
    }
  }
}

function replaceInText(
  text: string,
  state: LabelState,
  opts: MaskOptions
): string {
  let result = text;

  if (opts.maskIPs) {
    const ips = [...state.ipToLabel.entries()].sort(
      (a, b) => b[0].length - a[0].length
    );
    for (const [ip, label] of ips) {
      result = result.split(ip).join(label);
    }
  }

  if (opts.maskHostnames || opts.maskVersions) {
    const strings = [...state.stringToLabel.entries()].sort(
      (a, b) => b[0].length - a[0].length
    );
    for (const [str, label] of strings) {
      result = result.split(str).join(label);
    }
  }

  if (opts.maskPorts) {
    for (const [port, label] of state.portToLabel.entries()) {
      const portRegex = new RegExp(`\\b${port}/(tcp|udp)`, "g");
      result = result.replace(portRegex, `${label}/$1`);
    }
  }

  return result;
}

const IPV4_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

const H = "[0-9a-fA-F]{1,4}";
const IPV6_RE = new RegExp(
  [
    `(?:${H}:){7}${H}`,
    `(?:${H}:){6}:${H}`,
    `(?:${H}:){5}(?::${H}){1,2}`,
    `(?:${H}:){4}(?::${H}){1,3}`,
    `(?:${H}:){3}(?::${H}){1,4}`,
    `(?:${H}:){2}(?::${H}){1,5}`,
    `${H}:(?::${H}){1,6}`,
    `:(?::${H}){1,7}`,
    `fe80:(?::${H}){0,4}%[0-9a-zA-Z]+`,
    `(?:${H}:){1,7}:`,
    `::`,
  ].join("|"),
  "g"
);

const FQDN_RE =
  /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,}\b/g;

function isValidIpv4(ip: string): boolean {
  return ip.split(".").every((o) => {
    const n = parseInt(o, 10);
    return n >= 0 && n <= 255;
  });
}

function buildFqdnLabel(state: LabelState): string {
  const key = "fqdn";
  const count = (state.roleCounts.get(key) || 0) + 1;
  state.roleCounts.set(key, count);
  return `<<FQDN_${count}>>`;
}

function collectStrayIPs(
  rawText: string,
  state: LabelState,
  opts: MaskOptions
): void {
  if (!opts.maskIPs) return;

  let m: RegExpExecArray | null;
  while ((m = IPV4_RE.exec(rawText)) !== null) {
    const ip = m[1];
    if (state.ipToLabel.has(ip) || !isValidIpv4(ip)) continue;

    const label = buildStrayIpLabel(state);
    state.ipToLabel.set(ip, label);
    state.mappings.push({
      label,
      original: ip,
      confidence: "MAYBE",
      reason: "IP found in text",
    });
  }

  while ((m = IPV6_RE.exec(rawText)) !== null) {
    const ip = m[0];
    if (ip === "::") continue;
    if (state.ipToLabel.has(ip)) continue;

    const label = buildStrayIpLabel(state);
    state.ipToLabel.set(ip, label);
    state.mappings.push({
      label,
      original: ip,
      confidence: "MAYBE",
      reason: "IPv6 found in text",
    });
  }
}

function collectStrayDomains(
  rawText: string,
  state: LabelState,
  opts: MaskOptions
): void {
  if (!opts.maskHostnames) return;

  let m: RegExpExecArray | null;
  while ((m = FQDN_RE.exec(rawText)) !== null) {
    const domain = m[0];
    if (state.stringToLabel.has(domain)) continue;

    const label = buildFqdnLabel(state);
    state.stringToLabel.set(domain, label);
    state.mappings.push({
      label,
      original: domain,
      confidence: "MAYBE",
      reason: "FQDN found in text",
    });
  }
}

export function mask(
  hosts: HostEntry[],
  rawText: string,
  opts: MaskOptions
): Omit<MaskResult, "detectedSource"> {
  const state = initState();

  assignHostLabels(hosts, state, opts);
  collectStrayIPs(rawText, state, opts);
  collectStrayDomains(rawText, state, opts);
  const masked = replaceInText(rawText, state, opts);

  return {
    masked,
    mappingTable: state.mappings,
  };
}
