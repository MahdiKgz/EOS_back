import { randomUUID } from "node:crypto";
import {
  Column,
  CreateDateColumn,
  DeleteDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryColumn,
  UpdateDateColumn,
} from "typeorm";
import { AppUser } from "../users/user.entity";
export const deviceTypes = [
  "linux_edge",
  "esxi",
  "mikrotik",
  "fortigate",
  "pfsense",
  "generic_syslog_source",
  "generic_firewall",
  "nvr",
  "dvr",
] as const;
export const protocols = ["ssh", "api", "syslog", "agent"] as const;
export const environments = ["production", "staging", "lab"] as const;
export const statuses = ["unknown", "online", "offline", "error"] as const;
export type DeviceType = (typeof deviceTypes)[number];
@Entity("devices")
@Index("IDX_devices_workspace_created", ["workspaceOwnerId", "createdAt"])
@Index(
  "UQ_devices_endpoint",
  ["workspaceOwnerId", "vendor", "host", "managementPort", "protocol"],
  { unique: true, where: '"deletedAt" IS NULL' },
)
export class Device {
  @PrimaryColumn("text") id: string = randomUUID();
  @Column({ type: "text", nullable: true }) companyId!: string | null;
  @Column({ type: "text", nullable: true }) credentialId!: string | null;
  @Column({ type: "varchar", length: 16, default: "direct" }) accessRoute!: "direct";
  @Column("text") workspaceOwnerId!: string;
  @ManyToOne(() => AppUser, { onDelete: "CASCADE" })
  @JoinColumn({ name: "workspaceOwnerId" })
  owner!: AppUser;
  @Column({ type: "varchar", length: 120 }) name!: string;
  @Column({ type: "varchar", length: 80 }) vendor!: string;
  @Column({ type: "varchar", length: 40 }) type!: DeviceType;
  @Column({ type: "varchar", length: 253 }) host!: string;
  @Column("integer") managementPort!: number;
  @Column({ type: "varchar", length: 16 }) protocol!: (typeof protocols)[number];
  @Column({ type: "varchar", length: 16 }) environment!: (typeof environments)[number];
  @Column({ type: "text", array: true, default: () => "'{}'" }) tags!: string[];
  @Column({ type: "varchar", length: 16, default: "unknown" }) status!: (typeof statuses)[number];
  @Column({ type: "timestamptz", nullable: true }) lastSeenAt!: Date | null;
  @CreateDateColumn({ type: "timestamptz" }) createdAt!: Date;
  @UpdateDateColumn({ type: "timestamptz" }) updatedAt!: Date;
  @DeleteDateColumn({ type: "timestamptz" }) deletedAt!: Date | null;
}
