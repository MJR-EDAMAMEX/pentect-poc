import type { HostEntry, PortInfo } from "./types";

function looksLikeIP(s: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || s.includes(":");
}

export function parseNmapOutput(input: string): HostEntry[] {
  const hosts: HostEntry[] = [];
  const lines = input.split("\n");

  let current: HostEntry | null = null;

  for (const line of lines) {
    const trimmed = line.trim();

    const hostWithName = trimmed.match(
      /Nmap scan report for\s+(\S+)\s+\(([0-9a-fA-F:.]+)\)/
    );
    if (hostWithName) {
      if (current) hosts.push(current);
      current = { hostname: hostWithName[1], ip: hostWithName[2], ports: [] };
      continue;
    }

    const hostIpOnly = trimmed.match(
      /Nmap scan report for\s+([0-9a-fA-F:.]+)/
    );
    if (hostIpOnly && looksLikeIP(hostIpOnly[1])) {
      if (current) hosts.push(current);
      current = { hostname: "", ip: hostIpOnly[1], ports: [] };
      continue;
    }

    if (current) {
      const portLine = trimmed.match(
        /^(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?/
      );
      if (portLine) {
        const port: PortInfo = {
          port: parseInt(portLine[1], 10),
          protocol: portLine[2],
          state: portLine[3],
          service: portLine[4],
          version: (portLine[5] || "").trim(),
        };
        current.ports.push(port);
      }
    }
  }

  if (current) hosts.push(current);
  return hosts;
}
