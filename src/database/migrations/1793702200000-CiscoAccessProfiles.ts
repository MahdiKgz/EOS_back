import type { MigrationInterface, QueryRunner } from "typeorm";
export class CiscoAccessProfiles1793702200000 implements MigrationInterface {
  async up(q: QueryRunner): Promise<void> {
    await q.query(`CREATE TABLE cisco_enable_credentials (
      id text PRIMARY KEY,"ownerId" text NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
      name varchar(120) NOT NULL,"sealedSecret" text NOT NULL
    ); CREATE INDEX "IDX_enable_credentials_owner" ON cisco_enable_credentials("ownerId");
    CREATE TABLE device_cisco_access (
      "deviceId" text PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
      "compatibilityProfile" text NOT NULL DEFAULT 'modern' CHECK ("compatibilityProfile" IN ('modern','legacy_cisco')),
      "enableCredentialId" text REFERENCES cisco_enable_credentials(id) ON DELETE SET NULL,
      revision text NOT NULL
    );
`);
  }
  async down(): Promise<void> {
    /* Keep access settings and encrypted credentials. */
  }
}
