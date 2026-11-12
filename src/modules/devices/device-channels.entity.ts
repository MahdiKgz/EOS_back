import { Column, Entity, PrimaryColumn } from "typeorm";

@Entity("device_snmp_credentials")
export class DeviceSnmpCredential {
  @PrimaryColumn("text") id!: string;
  @Column("text") ownerId!: string;
  @Column("text") name!: string;
  @Column("text") username!: string;
  @Column("text") authProtocol!: "SHA" | "SHA256";
  @Column("text", { select: false }) sealedCredentials!: string;
}

export type SecondaryChannelMethod = "snmpv3" | "ssh" | "soap_api" | "rest_api";

@Entity("device_secondary_channels")
export class DeviceSecondaryChannel {
  @PrimaryColumn("text") deviceId!: string;
  @Column("text") method!: SecondaryChannelMethod;
  @Column("text", { nullable: true }) credentialId!: string | null;
  @Column("text", { nullable: true }) apiCredentialId!: string | null;
  @Column("text", { nullable: true }) snmpCredentialId!: string | null;
  @Column("text", { nullable: true }) host!: string | null;
  @Column("integer") port!: number;
  @Column("boolean", { default: false }) enabled!: boolean;
  @Column("integer", { default: 2 }) priority!: number;
  @Column("text") revision!: string;
  @Column("text", { default: "configured" }) status!: "configured" | "verified" | "error";
  @Column("text", { nullable: true, select: false }) verifiedBinding!: string | null;
  @Column("text", { nullable: true, select: false }) testToken!: string | null;
  @Column("timestamptz", { nullable: true }) testExpiresAt!: Date | null;
  @Column("timestamptz", { nullable: true }) lastTestAt!: Date | null;
  @Column("timestamptz", { nullable: true }) lastSuccessAt!: Date | null;
  @Column("text", { nullable: true }) lastError!: string | null;
  @Column("jsonb", { nullable: true }) telemetry!: {
    sysName: string;
    uptimeSeconds: number;
    interfaceCount: number | null;
  } | null;
}
