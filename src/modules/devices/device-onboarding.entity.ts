import { Column, Entity, PrimaryColumn } from "typeorm";

@Entity("device_companies")
export class DeviceCompany {
  @PrimaryColumn("text") id!: string;
  @Column("text") workspaceOwnerId!: string;
  @Column("text") name!: string;
}

@Entity("device_credentials")
export class DeviceCredential {
  @PrimaryColumn("text") id!: string;
  @Column("text") ownerId!: string;
  @Column("text") name!: string;
  @Column("text") username!: string;
  @Column("text", { select: false }) sealedCredentials!: string;
}
