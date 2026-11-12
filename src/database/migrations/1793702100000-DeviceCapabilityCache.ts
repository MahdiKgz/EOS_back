import type { MigrationInterface, QueryRunner } from "typeorm";
export class DeviceCapabilityCache1793702100000 implements MigrationInterface {
  async up(q: QueryRunner): Promise<void> {
    await q.query(`CREATE TABLE "device_capability_cache" (
      "deviceId" text PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
      "actorId" text REFERENCES app_users(id) ON DELETE SET NULL,
      "companyId" text,"binding" text,"snapshot" jsonb,
      "collectedAt" timestamptz,"expiresAt" timestamptz,
      "lastAttemptAt" timestamptz,"lastErrorCode" text,"leaseToken" text,"leaseExpiresAt" timestamptz
    );
    CREATE TABLE "device_capability_runs" (
      "id" text PRIMARY KEY,"deviceId" text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      "companyId" text,"actorName" text NOT NULL,"status" text NOT NULL CHECK ("status" IN ('collected','partial','unsupported','failed')),
      "platform" text,"startedAt" timestamptz NOT NULL,"completedAt" timestamptz NOT NULL,"errorCode" text,"commandCount" integer NOT NULL DEFAULT 0
    ); CREATE INDEX "IDX_capability_runs_recent" ON "device_capability_runs" ("deviceId","completedAt" DESC);`);
  }
  async down(): Promise<void> {
    /* Keep collection evidence. */
  }
}
