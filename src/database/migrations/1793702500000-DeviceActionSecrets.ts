import type { MigrationInterface, QueryRunner } from "typeorm";
export class DeviceActionSecrets1793702500000 implements MigrationInterface {
  async up(q: QueryRunner) {
    await q.query(`CREATE TABLE device_action_secrets (
      id text PRIMARY KEY,"ownerId" text NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
      purpose varchar(24) NOT NULL CHECK(purpose IN ('admin_password','ipsec_psk')),name varchar(120) NOT NULL,
      revision text NOT NULL,"sealedValue" text NOT NULL,
      UNIQUE("ownerId",purpose,name)
    )`);
  }
  async down() {
    /* Keep encrypted credentials and their references. */
  }
}
