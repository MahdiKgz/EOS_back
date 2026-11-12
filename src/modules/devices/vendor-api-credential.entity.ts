import { Column, Entity, PrimaryColumn } from "typeorm";
@Entity("device_api_credentials")
export class DeviceApiCredential {
  @PrimaryColumn("text") id!: string;
  @Column("text") ownerId!: string;
  @Column("text") name!: string;
  @Column("text") username!: string;
  @Column("text", { select: false }) sealedCredentials!: string;
}
