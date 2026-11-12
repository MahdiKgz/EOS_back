import { Column, Entity, PrimaryColumn } from "typeorm";
import type { FortiInventory } from "./fortigate-collector";
import type { CiscoInventory } from "./cisco-collector";
@Entity("device_capability_cache")
export class DeviceCapabilityCache {
  @PrimaryColumn("text") deviceId!: string;
  @Column("text", { nullable: true }) actorId!: string | null;
  @Column("text", { nullable: true }) companyId!: string | null;
  @Column("text", { nullable: true, select: false }) binding!: string | null;
  @Column("jsonb", { nullable: true }) snapshot!:
    ((CiscoInventory | FortiInventory) & { source: { host: string; port: number } }) | null;
  @Column("timestamptz", { nullable: true }) collectedAt!: Date | null;
  @Column("timestamptz", { nullable: true }) expiresAt!: Date | null;
  @Column("timestamptz", { nullable: true }) lastAttemptAt!: Date | null;
  @Column("text", { nullable: true }) lastErrorCode!: string | null;
  @Column("text", { nullable: true, select: false }) leaseToken!: string | null;
  @Column("timestamptz", { nullable: true, select: false }) leaseExpiresAt!: Date | null;
}
