import type { MigrationInterface, QueryRunner } from "typeorm";
export class CiscoAccessAudit1793702300000 implements MigrationInterface {
  async up(q: QueryRunner): Promise<void> {
    await q.query(`    CREATE TABLE device_cisco_access_events (
      id text PRIMARY KEY, "deviceId" text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      "companyId" text, "actorName" text NOT NULL, action text NOT NULL,
      "compatibilityProfile" text NOT NULL, "enableConfigured" boolean NOT NULL,
      "occurredAt" timestamptz NOT NULL DEFAULT now()
    ); CREATE INDEX "IDX_cisco_access_events_device" ON device_cisco_access_events("deviceId","occurredAt");`);
  }
  async down(): Promise<void> {
    /* Keep access audit history. */
  }
}
