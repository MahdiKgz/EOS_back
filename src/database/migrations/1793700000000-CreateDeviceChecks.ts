import { MigrationInterface, QueryRunner } from "typeorm";

export class CreateDeviceChecks1793700000000 implements MigrationInterface {
  name = "CreateDeviceChecks1793700000000";

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE "device_checks" (
        "id" SERIAL PRIMARY KEY,
        "deviceId" text NOT NULL,
        "host" varchar(253) NOT NULL,
        "status" varchar(16) NOT NULL,
        "latencyMs" double precision,
        "checkedAt" timestamptz NOT NULL,
        CONSTRAINT "FK_device_checks_device" FOREIGN KEY ("deviceId")
          REFERENCES "devices" ("id") ON DELETE CASCADE
      )
    `);
    await queryRunner.query(
      'CREATE INDEX "IDX_device_checks_device_time" ON "device_checks" ("deviceId", "checkedAt", "id")',
    );
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TABLE "device_checks"');
  }
}
