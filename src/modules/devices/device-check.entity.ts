import { Column, Entity, Index, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from "typeorm";
import { Device } from "./device.entity";

@Entity("device_checks")
@Index("IDX_device_checks_device_time", ["deviceId", "checkedAt", "id"])
export class DeviceCheck {
  @PrimaryGeneratedColumn("increment") id!: number;
  @Column("text") deviceId!: string;
  @ManyToOne(() => Device, { onDelete: "CASCADE" })
  @JoinColumn({ name: "deviceId", foreignKeyConstraintName: "FK_device_checks_device" })
  device!: Device;
  @Column({ type: "varchar", length: 253 }) host!: string;
  @Column({ type: "varchar", length: 16 }) status!: "online" | "offline";
  @Column({ type: "double precision", nullable: true }) latencyMs!: number | null;
  @Column("timestamptz") checkedAt!: Date;
}
