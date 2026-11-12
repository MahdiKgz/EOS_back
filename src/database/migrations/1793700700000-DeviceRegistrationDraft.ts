import { MigrationInterface, QueryRunner } from "typeorm";

export class DeviceRegistrationDraft1793700700000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE "device_registration_drafts" (
        "userId" text PRIMARY KEY REFERENCES "app_users"("id") ON DELETE CASCADE,
        "workspaceOwnerId" text NOT NULL REFERENCES "app_users"("id") ON DELETE CASCADE,
        "revision" uuid NOT NULL,
        "expiresAt" timestamptz NOT NULL,
        "draft" jsonb NOT NULL
      )
    `);
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TABLE "device_registration_drafts"');
  }
}
