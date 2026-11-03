import { Column, Entity, JoinColumn, OneToOne, PrimaryColumn } from "typeorm";
import { Device } from "./device.entity";

@Entity("device_ssh_profiles")
export class DeviceSshProfile {
  @PrimaryColumn("text", { primaryKeyConstraintName: "PK_device_ssh_profiles" })
  deviceId!: string;

  @OneToOne(() => Device, { onDelete: "CASCADE" })
  @JoinColumn({ name: "deviceId", foreignKeyConstraintName: "FK_device_ssh_profiles_device" })
  device!: Device;

  @Column("text")
  sealedCredentials!: string;
}
