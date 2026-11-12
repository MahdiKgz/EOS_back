import { MigrationInterface, QueryRunner } from "typeorm";

export class DeviceRestores1793701200000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE TABLE "device_restore_plans" (
      "id" uuid PRIMARY KEY,
      "deviceId" text NOT NULL REFERENCES "devices"("id") ON DELETE CASCADE,
      "requestedBy" text NOT NULL REFERENCES "app_users"("id") ON DELETE CASCADE,
      "workspaceOwnerId" text NOT NULL,
      "companyId" text,
      "artifactId" uuid NOT NULL,
      "filename" varchar(160) NOT NULL,
      "sha256" varchar(64) NOT NULL,
      "binding" varchar(64) NOT NULL,
      "actorName" varchar(80) NOT NULL,
      "status" varchar(16) NOT NULL DEFAULT 'ready' CHECK ("status" IN ('ready', 'running', 'succeeded', 'failed')),
      "state" varchar(40) NOT NULL DEFAULT 'preview_ready',
      "connectorInvoked" boolean NOT NULL DEFAULT false,
      "safetyBackupId" uuid,
      "createdAt" timestamptz NOT NULL DEFAULT now(),
      "expiresAt" timestamptz NOT NULL DEFAULT now() + interval '10 minutes',
      "startedAt" timestamptz,
      "finishedAt" timestamptz
    );
    CREATE INDEX "IDX_device_restore_recent" ON "device_restore_plans" ("deviceId", "createdAt" DESC);
    CREATE TABLE "device_restore_events" (
      "id" bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      "planId" uuid NOT NULL REFERENCES "device_restore_plans"("id") ON DELETE CASCADE,
      "action" varchar(24) NOT NULL CHECK ("action" IN ('preview', 'confirmed', 'safety_backup', 'apply_started', 'result')),
      "actorName" varchar(80) NOT NULL,
      "occurredAt" timestamptz NOT NULL DEFAULT now()
    );`);
  }
  async down(): Promise<void> {
    // Preserve execution outcomes and confirmation audit on rollback.
  }
}
