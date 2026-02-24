export type Confidence = "HIGH" | "LIKELY" | "MAYBE" | "UNKNOWN";

export type SourceType = "nmap" | "generic";

export interface MaskOptions {
  maskIPs: boolean;
  maskPorts: boolean;
  maskHostnames: boolean;
  maskVersions: boolean;
}

export const DEFAULT_MASK_OPTIONS: MaskOptions = {
  maskIPs: true,
  maskPorts: true,
  maskHostnames: true,
  maskVersions: true,
};

export interface PortInfo {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
}

export interface HostEntry {
  ip: string;
  hostname: string;
  ports: PortInfo[];
}

export interface PortRole {
  role: string;
  label: string;
  confidence: Confidence;
}

export interface HostRole {
  role: string;
  confidence: Confidence;
  reason: string;
}

export interface Mapping {
  label: string;
  original: string;
  confidence: Confidence;
  reason: string;
}

export interface MaskResult {
  masked: string;
  mappingTable: Mapping[];
}
