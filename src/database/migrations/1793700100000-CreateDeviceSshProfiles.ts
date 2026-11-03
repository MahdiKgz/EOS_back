import { MigrationInterface, QueryRunner } from "typeorm";

export class CreateDeviceSshProfiles1793700100000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE "device_ssh_profiles" (
        "deviceId" text NOT NULL,
        "sealedCredentials" text NOT NULL,
        CONSTRAINT "PK_device_ssh_profiles" PRIMARY KEY ("deviceId"),
        CONSTRAINT "FK_device_ssh_profiles_device" FOREIGN KEY ("deviceId")
          REFERENCES "devices" ("id") ON DELETE CASCADE
      )
    `);
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TABLE "device_ssh_profiles"');
  }
}
