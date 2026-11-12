import { MigrationInterface, QueryRunner } from "typeorm";

export class RecorderCredentials1793700500000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('ALTER TABLE "devices" ADD "sealedRecorderCredentials" text');
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('ALTER TABLE "devices" DROP COLUMN "sealedRecorderCredentials"');
  }
}
