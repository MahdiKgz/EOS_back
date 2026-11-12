import type { MigrationInterface, QueryRunner } from "typeorm";
export class DeviceMonitoring1793702000000 implements MigrationInterface {
  async up(q: QueryRunner): Promise<void> {
    await q.query(`CREATE TABLE "device_monitoring" (
      "deviceId" text PRIMARY KEY REFERENCES "devices"("id") ON DELETE CASCADE,
      "actorId" text NOT NULL REFERENCES "app_users"("id") ON DELETE CASCADE,
      "enabled" boolean NOT NULL DEFAULT false,
      "intervalSeconds" integer NOT NULL DEFAULT 300 CHECK ("intervalSeconds" IN (60,300,900)),
      "revision" text NOT NULL, "nextRunAt" timestamptz,
      "leaseToken" text, "leaseExpiresAt" timestamptz,
      "lastAttemptAt" timestamptz, "lastSuccessAt" timestamptz, "lastErrorCode" text,
      "failures" integer NOT NULL DEFAULT 0,
      "authorizedBindings" text[] NOT NULL DEFAULT '{}', "generation" text, "counterEpoch" text, "latest" jsonb
    ); CREATE INDEX "IDX_monitoring_due" ON "device_monitoring" ("nextRunAt") WHERE "enabled"=true;
    CREATE TABLE "device_monitor_runs" (
      "id" text PRIMARY KEY, "deviceId" text NOT NULL REFERENCES "devices"("id") ON DELETE CASCADE,
      "companyId" text, "actorId" text NOT NULL, "status" text NOT NULL CHECK ("status" IN ('success','failed')),
      "source" jsonb, "startedAt" timestamptz NOT NULL, "completedAt" timestamptz NOT NULL,
      "errorCode" text, "measurementCount" integer NOT NULL DEFAULT 0, "warnings" jsonb NOT NULL DEFAULT '[]'
    ); CREATE INDEX "IDX_monitor_runs_recent" ON "device_monitor_runs" ("deviceId","completedAt" DESC,"id");
    CREATE TABLE "device_metric_buckets" (
      "deviceId" text NOT NULL REFERENCES "devices"("id") ON DELETE CASCADE,
      "companyKey" text NOT NULL, "generation" text NOT NULL, "counterEpoch" text NOT NULL DEFAULT '',
      "metricKey" varchar(80) NOT NULL, "label" varchar(128) NOT NULL DEFAULT '', "unit" varchar(16) NOT NULL,
      "kind" text NOT NULL CHECK ("kind" IN ('gauge','counter')),
      "resolution" integer NOT NULL CHECK ("resolution" IN (300,3600)), "bucketAt" timestamptz NOT NULL,
      "firstAt" timestamptz NOT NULL, "lastAt" timestamptz NOT NULL,
      "firstValue" double precision NOT NULL, "lastValue" double precision NOT NULL,
      "sumValue" double precision NOT NULL, "sampleCount" integer NOT NULL,
      PRIMARY KEY ("deviceId","companyKey","generation","counterEpoch","metricKey","label","resolution","bucketAt")
    ); CREATE INDEX "IDX_metric_buckets_age" ON "device_metric_buckets" ("deviceId","bucketAt");`);
  }
  async down(): Promise<void> {
    /* Monitoring history is retained. */
  }
}
