import type { Confidence, HostEntry, HostRole, PortRole } from "./types";

const PORT_MAP: Record<number, PortRole> = {
  21:    { role: "FTP",    label: "ftp",           confidence: "HIGH" },
  22:    { role: "SSH",    label: "ssh",           confidence: "HIGH" },
  25:    { role: "SMTP",   label: "smtp",          confidence: "HIGH" },
  53:    { role: "DNS",    label: "dns",           confidence: "HIGH" },
  389:   { role: "AD",     label: "ldap",          confidence: "HIGH" },
  445:   { role: "SMB",    label: "smb",           confidence: "HIGH" },
  636:   { role: "AD",     label: "ldaps",         confidence: "HIGH" },
  1433:  { role: "DB",     label: "mssql",         confidence: "HIGH" },
  1521:  { role: "DB",     label: "oracle",        confidence: "HIGH" },
  3389:  { role: "RDP",    label: "rdp",           confidence: "HIGH" },
  5432:  { role: "DB",     label: "postgres",      confidence: "HIGH" },
  33060: { role: "DB",     label: "mysqlx",        confidence: "HIGH" },
  80:    { role: "WEB",    label: "http",          confidence: "LIKELY" },
  443:   { role: "WEB",    label: "https",         confidence: "LIKELY" },
  3306:  { role: "DB",     label: "mysql",         confidence: "LIKELY" },
  6379:  { role: "CACHE",  label: "redis",         confidence: "LIKELY" },
  27017: { role: "DB",     label: "mongodb",       confidence: "LIKELY" },
  8080:  { role: "WEB",    label: "http_alt",      confidence: "MAYBE" },
  8443:  { role: "WEB",    label: "https_alt",     confidence: "MAYBE" },
  4444:  { role: "C2",     label: "c2",            confidence: "MAYBE" },
  9200:  { role: "SEARCH", label: "elasticsearch", confidence: "MAYBE" },
};

const CONFIDENCE_RANK: Record<Confidence, number> = {
  HIGH: 3,
  LIKELY: 2,
  MAYBE: 1,
  UNKNOWN: 0,
};

interface ComboRule {
  ports: number[];
  role: string;
  confidence: Confidence;
  reason: string;
}

const COMBO_RULES: ComboRule[] = [
  {
    ports: [3306, 33060],
    role: "DB",
    confidence: "HIGH",
    reason: "port 3306+33060 → MySQL confirmed",
  },
  {
    ports: [80, 443],
    role: "WEB",
    confidence: "HIGH",
    reason: "port 80+443 → web server confirmed",
  },
  {
    ports: [8080, 8443],
    role: "WEB",
    confidence: "LIKELY",
    reason: "port 8080+8443 → likely web server",
  },
  {
    ports: [443, 389],
    role: "AD",
    confidence: "HIGH",
    reason: "port 389(ldap) + 443 → AD with web interface",
  },
  {
    ports: [636, 443],
    role: "AD",
    confidence: "HIGH",
    reason: "port 636(ldaps) + 443 → AD confirmed",
  },
  {
    ports: [1433, 3389],
    role: "DB",
    confidence: "HIGH",
    reason: "port 1433(mssql) + 3389(rdp) → Windows DB server",
  },
];

export function classifyHost(host: HostEntry): HostRole {
  const openPorts = host.ports
    .filter((p) => p.state === "open")
    .map((p) => p.port);

  if (openPorts.length === 0) {
    return { role: "UNKNOWN", confidence: "UNKNOWN", reason: "no open ports" };
  }

  for (const rule of COMBO_RULES) {
    if (rule.ports.every((p) => openPorts.includes(p))) {
      return {
        role: rule.role,
        confidence: rule.confidence,
        reason: rule.reason,
      };
    }
  }

  let best: PortRole | null = null;
  let bestPort = 0;
  for (const port of openPorts) {
    const mapped = PORT_MAP[port];
    if (mapped) {
      if (
        !best ||
        CONFIDENCE_RANK[mapped.confidence] > CONFIDENCE_RANK[best.confidence]
      ) {
        best = mapped;
        bestPort = port;
      }
    }
  }

  if (best) {
    return {
      role: best.role,
      confidence: best.confidence,
      reason: `port ${bestPort} → ${best.role.toLowerCase()}`,
    };
  }

  return {
    role: "UNKNOWN",
    confidence: "UNKNOWN",
    reason: "no known port signatures",
  };
}

export function getPortRole(port: number): PortRole | undefined {
  return PORT_MAP[port];
}
