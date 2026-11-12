import { MigrationInterface, QueryRunner } from "typeorm";

export class DeviceLocation1793700600000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('ALTER TABLE "devices" ADD "location" varchar(160)');
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('ALTER TABLE "devices" DROP COLUMN "location"');
  }
}
