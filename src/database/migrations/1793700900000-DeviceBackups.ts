import { MigrationInterface, QueryRunner } from "typeorm";

export class DeviceBackups1793700900000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE "device_backups" (
        "id" uuid PRIMARY KEY,
        "deviceId" text NOT NULL REFERENCES "devices"("id") ON DELETE CASCADE,
        "companyId" text,
        "workspaceOwnerId" text NOT NULL REFERENCES "app_users"("id") ON DELETE CASCADE,
        "filename" varchar(160) NOT NULL,
        "sha256" varchar(64) NOT NULL,
        "byteLength" integer NOT NULL,
        "sealedContent" bytea NOT NULL,
        "createdAt" timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX "IDX_device_backups_recent" ON "device_backups" ("deviceId", "createdAt" DESC, "id");
      CREATE TABLE "device_backup_events" (
        "id" bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        "deviceId" text NOT NULL REFERENCES "devices"("id") ON DELETE CASCADE,
        "backupId" uuid,
        "actorName" varchar(80) NOT NULL,
        "action" varchar(16) NOT NULL CHECK ("action" IN ('created', 'failed', 'downloaded', 'file_deleted')),
        "occurredAt" timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX "IDX_device_backup_events_recent" ON "device_backup_events" ("deviceId", "occurredAt" DESC, "id" DESC);
    `);
  }
  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TABLE "device_backup_events", "device_backups"');
  }
}
