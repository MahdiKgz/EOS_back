import { MigrationInterface, QueryRunner } from "typeorm";

export class DeviceVerification1793700400000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('ALTER TABLE "devices" ADD "verification" jsonb');
    await queryRunner.query(`
      CREATE FUNCTION invalidate_device_verification() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        UPDATE "devices" SET "verification" = NULL
        WHERE "credentialId" = OLD.id AND "verification" IS NOT NULL;
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
      END;
      $$;
      CREATE TRIGGER invalidate_device_verification
      BEFORE UPDATE OF "sealedCredentials" OR DELETE ON "device_credentials"
      FOR EACH ROW EXECUTE FUNCTION invalidate_device_verification();
    `);
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TRIGGER invalidate_device_verification ON "device_credentials"');
    await queryRunner.query("DROP FUNCTION invalidate_device_verification()");
    await queryRunner.query('ALTER TABLE "devices" DROP COLUMN "verification"');
  }
}
