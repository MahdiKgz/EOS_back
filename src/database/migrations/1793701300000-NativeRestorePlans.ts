import { MigrationInterface, QueryRunner } from "typeorm";
export class NativeRestorePlans1793701300000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "device_restore_plans"
      ADD COLUMN "vendor" varchar(16) NOT NULL DEFAULT 'linux' CHECK ("vendor" IN ('linux', 'cisco', 'mikrotik', 'fortigate')),
      ADD COLUMN "heartbeatAt" timestamptz;
      UPDATE "device_restore_plans" SET "heartbeatAt" = "startedAt" WHERE "status" = 'running';
      ALTER TABLE "device_restore_events" DROP CONSTRAINT "device_restore_events_action_check";
      ALTER TABLE "device_restore_events" ADD CONSTRAINT "device_restore_events_action_check" CHECK ("action" IN ('preview', 'confirmed', 'safety_backup', 'apply_started', 'result', 'verified'));`);
  }
  async down(): Promise<void> {
    /* Preserve native restore outcomes and their audit. */
  }
}
