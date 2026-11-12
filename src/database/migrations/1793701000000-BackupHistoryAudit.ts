import { MigrationInterface, QueryRunner } from "typeorm";

export class BackupHistoryAudit1793701000000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "device_backup_events"
      DROP CONSTRAINT "device_backup_events_action_check",
      ADD CONSTRAINT "device_backup_events_action_check"
      CHECK ("action" IN ('created', 'failed', 'downloaded', 'file_deleted', 'history_cleared'))`);
  }
  async down(): Promise<void> {
    // Clearing-history audit records remain valid after a rollback.
  }
}
