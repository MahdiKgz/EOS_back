import { Column, Entity, PrimaryColumn } from "typeorm";
import type { MonitoringSnapshot } from "./monitoring.types";
@Entity("device_monitoring")
export class DeviceMonitoring {
  @PrimaryColumn("text") deviceId!: string;
  @Column("text") actorId!: string;
  @Column("boolean") enabled!: boolean;
  @Column("integer") intervalSeconds!: number;
  @Column("text") revision!: string;
  @Column("timestamptz", { nullable: true }) nextRunAt!: Date | null;
  @Column("text", { nullable: true }) leaseToken!: string | null;
  @Column("timestamptz", { nullable: true }) leaseExpiresAt!: Date | null;
  @Column("timestamptz", { nullable: true }) lastAttemptAt!: Date | null;
  @Column("timestamptz", { nullable: true }) lastSuccessAt!: Date | null;
  @Column("text", { nullable: true }) lastErrorCode!: string | null;
  @Column("integer") failures!: number;
  @Column("text", { array: true, default: () => "'{}'" }) authorizedBindings!: string[];
  @Column("text", { nullable: true }) generation!: string | null;
  @Column("text", { nullable: true }) counterEpoch!: string | null;
  @Column("jsonb", { nullable: true }) latest!: MonitoringSnapshot | null;
}
