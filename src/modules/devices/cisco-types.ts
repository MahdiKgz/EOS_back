export type PlatformDetectionResult = {
  vendor: "cisco";
  platform: string;
  version: string | null;
  model: string | null;
  hostname: string | null;
  confidence: number;
  evidence: string[];
  supported: boolean;
};
export type CiscoFailure =
  | "CISCO_COMMAND_NOT_SUPPORTED"
  | "CISCO_COMMAND_REQUIRES_PRIVILEGE"
  | "CISCO_COMMAND_FAILED"
  | "CISCO_OUTPUT_LIMIT"
  | "CISCO_DEADLINE";
