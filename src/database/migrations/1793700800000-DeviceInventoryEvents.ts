import { MigrationInterface, QueryRunner } from "typeorm";

export class DeviceInventoryEvents1793700800000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE "device_inventory_events" (
        "id" bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        "deviceId" text NOT NULL REFERENCES "devices"("id") ON DELETE CASCADE,
        "actorName" varchar(80) NOT NULL,
        "action" varchar(16) NOT NULL CHECK ("action" IN ('archived', 'restored', 'transferred')),
        "occurredAt" timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX "IDX_device_inventory_events_recent"
      ON "device_inventory_events" ("deviceId", "occurredAt" DESC, "id" DESC);
    `);
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TABLE "device_inventory_events"');
  }
}
