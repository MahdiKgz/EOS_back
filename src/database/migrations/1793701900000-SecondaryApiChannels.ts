import type { MigrationInterface, QueryRunner } from "typeorm";
export class SecondaryApiChannels1793701900000 implements MigrationInterface {
  async up(q: QueryRunner): Promise<void> {
    await q.query(`ALTER TABLE "device_secondary_channels"
      ADD COLUMN "apiCredentialId" text REFERENCES "device_api_credentials"("id") ON DELETE SET NULL;
    ALTER TABLE "device_secondary_channels" DROP CONSTRAINT "device_secondary_channels_method_check";
    ALTER TABLE "device_secondary_channels" ADD CONSTRAINT "device_secondary_channels_method_check"
      CHECK ("method" IN ('snmpv3','ssh','soap_api','rest_api'));
    CREATE INDEX "IDX_secondary_api_credential" ON "device_secondary_channels" ("apiCredentialId");`);
  }
  async down(): Promise<void> {
    /* Preserve configured connection channels. */
  }
}
