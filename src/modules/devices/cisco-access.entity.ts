import { Column, Entity, PrimaryColumn } from "typeorm";
@Entity("cisco_enable_credentials")
export class CiscoEnableCredential {
  @PrimaryColumn("text") id!: string;
  @Column("text") ownerId!: string;
  @Column("varchar", { length: 120 }) name!: string;
  @Column("text", { select: false }) sealedSecret!: string;
}
@Entity("device_cisco_access")
export class DeviceCiscoAccess {
  @PrimaryColumn("text") deviceId!: string;
  @Column("text") compatibilityProfile!: "modern" | "legacy_cisco";
  @Column("text", { nullable: true }) enableCredentialId!: string | null;
  @Column("text") revision!: string;
}
