import { Column, Entity, PrimaryColumn } from "typeorm";
@Entity("device_action_secrets")
export class DeviceActionSecret {
  @PrimaryColumn("text") id!: string;
  @Column("text") ownerId!: string;
  @Column("varchar", { length: 24 }) purpose!: "admin_password" | "ipsec_psk";
  @Column("varchar", { length: 120 }) name!: string;
  @Column("text") revision!: string;
  @Column("text", { select: false }) sealedValue!: string;
}
