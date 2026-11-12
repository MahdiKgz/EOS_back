import { MigrationInterface, QueryRunner } from "typeorm";
export class BackupActivitySelections1793701500000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE TABLE "backup_activity_selections" (
      "id" uuid PRIMARY KEY,
      "actorId" text NOT NULL REFERENCES "app_users"("id") ON DELETE CASCADE,
      "workspaceOwnerId" text NOT NULL,
      "scope" varchar(16) NOT NULL DEFAULT 'workspace' CHECK ("scope" IN ('workspace', 'device')),
      "filters" jsonb NOT NULL,
      "devices" jsonb NOT NULL,
      "eventIds" bigint[] NOT NULL,
      "count" integer NOT NULL,
      "deletedCount" integer,
      "consumedAt" timestamptz,
      "expiresAt" timestamptz NOT NULL DEFAULT clock_timestamp() + interval '5 minutes'
    );
    CREATE INDEX "IDX_backup_activity_selection_expiry" ON "backup_activity_selections" ("expiresAt");
    CREATE INDEX "IDX_backup_activity_selection_actor" ON "backup_activity_selections" ("actorId") WHERE "consumedAt" IS NULL;`);
  }
  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TABLE "backup_activity_selections"');
  }
}
