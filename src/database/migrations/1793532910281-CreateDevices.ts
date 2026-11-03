import { MigrationInterface, QueryRunner } from "typeorm";

export class CreateDevices1793532910281 implements MigrationInterface {
  name = "CreateDevices1793532910281";

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "devices" ("id" text NOT NULL, "workspaceOwnerId" text NOT NULL, "name" character varying(120) NOT NULL, "vendor" character varying(80) NOT NULL, "type" character varying(40) NOT NULL, "host" character varying(253) NOT NULL, "managementPort" integer NOT NULL, "protocol" character varying(16) NOT NULL, "environment" character varying(16) NOT NULL, "tags" text array NOT NULL DEFAULT '{}', "status" character varying(16) NOT NULL DEFAULT 'unknown', "lastSeenAt" TIMESTAMP WITH TIME ZONE, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "deletedAt" TIMESTAMP WITH TIME ZONE, CONSTRAINT "PK_b1514758245c12daf43486dd1f0" PRIMARY KEY ("id"))`,
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX "UQ_devices_endpoint" ON "devices" ("workspaceOwnerId", "vendor", "host", "managementPort", "protocol") WHERE "deletedAt" IS NULL`,
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_devices_workspace_created" ON "devices" ("workspaceOwnerId", "createdAt") `,
    );
    await queryRunner.query(
      `ALTER TABLE "devices" ADD CONSTRAINT "FK_0d8d59aeebe6e249049ffabcb03" FOREIGN KEY ("workspaceOwnerId") REFERENCES "app_users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "devices" DROP CONSTRAINT "FK_0d8d59aeebe6e249049ffabcb03"`,
    );
    await queryRunner.query(`DROP INDEX "public"."IDX_devices_workspace_created"`);
    await queryRunner.query(`DROP INDEX "public"."UQ_devices_endpoint"`);
    await queryRunner.query(`DROP TABLE "devices"`);
  }
}
