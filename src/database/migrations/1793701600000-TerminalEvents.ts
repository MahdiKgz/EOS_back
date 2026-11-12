import { MigrationInterface, QueryRunner } from "typeorm";
export class TerminalEvents1793701600000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE TABLE "device_terminal_events" (
      "id" bigserial PRIMARY KEY,
      "deviceId" text NOT NULL REFERENCES "devices"("id") ON DELETE CASCADE,
      "sessionId" uuid NOT NULL, "actorId" text NOT NULL, "actorName" text NOT NULL,
      "action" varchar(16) NOT NULL CHECK ("action" IN ('requested','connected','closed')),
      "reason" varchar(64), "inputBytes" bigint, "outputBytes" bigint, "durationMs" bigint,
      "occurredAt" timestamptz NOT NULL DEFAULT clock_timestamp()
    ); CREATE INDEX "IDX_terminal_events_device_recent" ON "device_terminal_events" ("deviceId", "occurredAt" DESC, "id" DESC);`);
  }
  async down(): Promise<void> {
    /* Preserve session audit. */
  }
}
