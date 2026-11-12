import type { Device } from "./device.entity";
import type { ApiSecret } from "./ssh-credential-vault";
import type { SshCredentials } from "./linux-ssh";
import type { SnmpSecret } from "./snmpv3";
export type Measurement = {
  key: string;
  value: number;
  unit: string;
  label: string;
  kind: "gauge" | "counter";
};
export type MonitorSource = {
  role: "management" | "observability";
  method: "ssh" | "api" | "snmpv3" | "soap_api" | "rest_api";
  host: string;
  port: number;
};
export type ResolvedMonitorSource = {
  source: MonitorSource;
  device: Device;
  credentials: ApiSecret | SshCredentials | SnmpSecret;
  binding: string;
};
export type MonitoringSnapshot = {
  actorId: string;
  measurements: Measurement[];
  warnings: string[];
  source: MonitorSource;
  collectedAt: string;
  binding: string;
  companyId: string | null;
};
