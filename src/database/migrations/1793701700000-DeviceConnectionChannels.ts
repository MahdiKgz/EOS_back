import type { MigrationInterface, QueryRunner } from "typeorm";
export class DeviceConnectionChannels1793701700000 implements MigrationInterface {
  async up(q: QueryRunner): Promise<void> {
    await q.query(`CREATE TABLE "device_snmp_credentials" (
      "id" text PRIMARY KEY, "ownerId" text NOT NULL REFERENCES "app_users"("id") ON DELETE CASCADE,
      "name" text NOT NULL, "username" text NOT NULL, "authProtocol" text NOT NULL CHECK ("authProtocol" IN ('SHA','SHA256')),
      "sealedCredentials" text NOT NULL
    ); CREATE INDEX "IDX_snmp_credentials_owner" ON "device_snmp_credentials" ("ownerId");
    CREATE TABLE "device_secondary_channels" (
      "deviceId" text PRIMARY KEY REFERENCES "devices"("id") ON DELETE CASCADE,
      "method" text NOT NULL CHECK ("method" IN ('snmpv3','ssh')),
      "credentialId" text REFERENCES "device_credentials"("id") ON DELETE SET NULL,
      "snmpCredentialId" text REFERENCES "device_snmp_credentials"("id") ON DELETE SET NULL,
      "host" text, "port" integer NOT NULL CHECK ("port" BETWEEN 1 AND 65535),
      "enabled" boolean NOT NULL DEFAULT false, "priority" integer NOT NULL DEFAULT 2 CHECK ("priority" IN (1,2)),
      "revision" text NOT NULL, "status" text NOT NULL DEFAULT 'configured' CHECK ("status" IN ('configured','verified','error')),
      "verifiedBinding" text, "testToken" text, "testExpiresAt" timestamptz,
      "lastTestAt" timestamptz, "lastSuccessAt" timestamptz, "lastError" text, "telemetry" jsonb
    ); CREATE TABLE "device_channel_tests" (
      "id" bigserial PRIMARY KEY, "deviceId" text NOT NULL REFERENCES "devices"("id") ON DELETE CASCADE,
      "method" text NOT NULL, "connected" boolean NOT NULL, "errorCode" text,
      "actorId" text NOT NULL, "checkedAt" timestamptz NOT NULL DEFAULT clock_timestamp()
    ); CREATE INDEX "IDX_channel_tests_recent" ON "device_channel_tests" ("deviceId","checkedAt" DESC,"id" DESC);`);
  }
  async down(): Promise<void> {
    /* Preserve connection configuration and audit. */
  }
}
