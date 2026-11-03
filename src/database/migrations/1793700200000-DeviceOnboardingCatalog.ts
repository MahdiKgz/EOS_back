import { MigrationInterface, QueryRunner } from "typeorm";

export class DeviceOnboardingCatalog1793700200000 implements MigrationInterface {
  async up(queryRunner: QueryRunner) {
    await queryRunner.query(`
      CREATE TABLE device_companies (
        id text PRIMARY KEY, "workspaceOwnerId" text NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
        name text NOT NULL, UNIQUE ("workspaceOwnerId", name)
      );
      CREATE TABLE device_credentials (
        id text PRIMARY KEY, "ownerId" text NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
        name text NOT NULL, username text NOT NULL, "sealedCredentials" text NOT NULL
      );
      CREATE INDEX ON device_credentials ("ownerId");
      ALTER TABLE devices ADD COLUMN "companyId" text REFERENCES device_companies(id) ON DELETE SET NULL;
      ALTER TABLE devices ADD COLUMN "credentialId" text REFERENCES device_credentials(id) ON DELETE SET NULL;
      ALTER TABLE devices ADD COLUMN "accessRoute" varchar(16) NOT NULL DEFAULT 'direct';
      INSERT INTO device_companies (id, "workspaceOwnerId", name)
        SELECT DISTINCT "workspaceOwnerId", "workspaceOwnerId", 'شرکت اصلی' FROM devices;
      UPDATE devices SET "companyId" = "workspaceOwnerId";
    `);
  }
  async down(queryRunner: QueryRunner) {
    await queryRunner.query(`
      ALTER TABLE devices DROP COLUMN "companyId", DROP COLUMN "credentialId", DROP COLUMN "accessRoute";
      DROP TABLE device_credentials;
      DROP TABLE device_companies;
    `);
  }
}
