import { MigrationInterface, QueryRunner } from "typeorm";
export class BackupActivityMetadata1793701400000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "device_backup_events"
      ADD COLUMN "actorId" text,
      ADD COLUMN "actorUsername" varchar(64),
      ADD COLUMN "deviceName" varchar(120),
      ADD COLUMN "host" varchar(253),
      ADD COLUMN "vendor" varchar(80),
      ADD COLUMN "companyName" text,
      ADD COLUMN "filename" varchar(160),
      ADD COLUMN "byteLength" integer,
      ADD COLUMN "sha256" varchar(64),
      ADD COLUMN "durationMs" integer,
      ADD COLUMN "deletedCount" integer,
      ADD COLUMN "failureCode" varchar(32);
      UPDATE "device_backup_events" event SET "filename" = file."filename", "byteLength" = file."byteLength", "sha256" = file."sha256"
        FROM "device_backups" file WHERE event."backupId" = file."id" AND event."deviceId" = file."deviceId";
      CREATE INDEX "IDX_backup_activity_recent" ON "device_backup_events" ("occurredAt" DESC, "id" DESC);`);
  }
  async down(): Promise<void> {
    /* Preserve captured audit metadata on rollback. */
  }
}
