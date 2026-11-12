import { MigrationInterface, QueryRunner } from "typeorm";

export class BackupArtifacts1793701100000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "device_backups" ADD COLUMN "origin" varchar(16) NOT NULL DEFAULT 'collected'
        CHECK ("origin" IN ('collected', 'uploaded'));
      ALTER TABLE "device_backups" ADD COLUMN "deviceType" varchar(40);
      UPDATE "device_backups" file SET "deviceType" = device."type" FROM "devices" device WHERE file."deviceId" = device."id";
      ALTER TABLE "device_backups" ALTER COLUMN "deviceType" SET NOT NULL;
      ALTER TABLE "device_backup_events" DROP CONSTRAINT "device_backup_events_action_check";
      ALTER TABLE "device_backup_events" ADD CONSTRAINT "device_backup_events_action_check"
        CHECK ("action" IN ('created', 'failed', 'downloaded', 'file_deleted', 'history_cleared', 'uploaded'));
      CREATE INDEX "IDX_backup_uploaded_workspace" ON "device_backups" ("workspaceOwnerId") WHERE "origin" = 'uploaded';
    `);
  }
  async down(): Promise<void> {
    // Uploaded artifacts and their audit records must remain readable on rollback.
  }
}
