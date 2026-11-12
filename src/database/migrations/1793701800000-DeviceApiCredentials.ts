import type { MigrationInterface, QueryRunner } from "typeorm";
export class DeviceApiCredentials1793701800000 implements MigrationInterface {
  async up(q: QueryRunner): Promise<void> {
    await q.query(`CREATE TABLE "device_api_credentials" (
      "id" text PRIMARY KEY, "ownerId" text NOT NULL REFERENCES "app_users"("id") ON DELETE CASCADE,
      "name" text NOT NULL, "username" text NOT NULL, "sealedCredentials" text NOT NULL
    ); CREATE INDEX "IDX_api_credentials_owner" ON "device_api_credentials" ("ownerId");
    ALTER TABLE "devices" ADD COLUMN "apiCredentialId" text REFERENCES "device_api_credentials"("id") ON DELETE SET NULL;
    CREATE INDEX "IDX_devices_api_credential" ON "devices" ("apiCredentialId");`);
  }
  async down(): Promise<void> {
    /* Preserve encrypted connection references. */
  }
}
