import { MigrationInterface, QueryRunner } from "typeorm";

export class PruneDeviceChecks1793700300000 implements MigrationInterface {
  async up(queryRunner: QueryRunner) {
    await queryRunner.query(`
      DELETE FROM "device_checks" WHERE "id" IN (
        SELECT "id" FROM (
          SELECT "id", ROW_NUMBER() OVER (
            PARTITION BY "deviceId" ORDER BY "checkedAt" DESC, "id" DESC
          ) AS position
          FROM "device_checks"
        ) AS ranked
        WHERE position > 5
      )
    `);
  }

  async down(): Promise<void> {
    // Pruned history cannot be recovered by rolling back this migration.
  }
}
