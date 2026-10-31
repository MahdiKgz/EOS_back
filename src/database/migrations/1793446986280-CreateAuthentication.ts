import { MigrationInterface, QueryRunner } from "typeorm";

export class CreateAuthentication1793446986280 implements MigrationInterface {
    name = 'CreateAuthentication1793446986280'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TYPE "public"."app_users_role_enum" AS ENUM('pl_admin', 'co_admin', 'co_employee')`);
        await queryRunner.query(`CREATE TABLE "app_users" ("id" text NOT NULL, "username" character varying(64) NOT NULL, "email" character varying(160), "phone" character varying(24), "passwordHash" text NOT NULL, "displayName" character varying(80) NOT NULL, "role" "public"."app_users_role_enum" NOT NULL DEFAULT 'co_employee', "isActive" boolean NOT NULL DEFAULT true, "allowedSections" text array NOT NULL DEFAULT '{}', "workspaceOwnerId" text, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "UQ_5d67cc2e38c80255e768c2b76a9" UNIQUE ("username"), CONSTRAINT "UQ_14241fb016a330600a7e0efae93" UNIQUE ("email"), CONSTRAINT "UQ_e0fa7f6d1b9f2d22a66fffcee6b" UNIQUE ("phone"), CONSTRAINT "PK_9b97e4fbff9c2f3918fda27f999" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_c90415db608ff4dcd5737ff592" ON "app_users" ("workspaceOwnerId") `);
        await queryRunner.query(`CREATE TABLE "password_resets" ("id" text NOT NULL, "userId" text NOT NULL, "tokenHash" text NOT NULL, "expiresAt" TIMESTAMP WITH TIME ZONE NOT NULL, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "UQ_7f6aae0fcc807c9e7194ca5cc4a" UNIQUE ("tokenHash"), CONSTRAINT "PK_4816377aa98211c1de34469e742" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_d95569f623f28a0bf034a55099" ON "password_resets" ("userId") `);
        await queryRunner.query(`CREATE TABLE "auth_sessions" ("id" text NOT NULL, "userId" text NOT NULL, "tokenHash" text NOT NULL, "activeCompanyId" text, "expiresAt" TIMESTAMP WITH TIME ZONE NOT NULL, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "lastSeenAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "userAgent" character varying(500), "ipAddress" character varying(64), CONSTRAINT "UQ_124a43dd73c87052e1a6193e3b6" UNIQUE ("tokenHash"), CONSTRAINT "PK_641507381f32580e8479efc36cd" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_925b24d7fc2f9324ce972aee02" ON "auth_sessions" ("userId") `);
        await queryRunner.query(`CREATE INDEX "IDX_4d5b325649caf1628a6e2e2be1" ON "auth_sessions" ("expiresAt") `);
        await queryRunner.query(`ALTER TABLE "password_resets" ADD CONSTRAINT "FK_d95569f623f28a0bf034a55099e" FOREIGN KEY ("userId") REFERENCES "app_users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "auth_sessions" ADD CONSTRAINT "FK_925b24d7fc2f9324ce972aee025" FOREIGN KEY ("userId") REFERENCES "app_users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "auth_sessions" DROP CONSTRAINT "FK_925b24d7fc2f9324ce972aee025"`);
        await queryRunner.query(`ALTER TABLE "password_resets" DROP CONSTRAINT "FK_d95569f623f28a0bf034a55099e"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_4d5b325649caf1628a6e2e2be1"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_925b24d7fc2f9324ce972aee02"`);
        await queryRunner.query(`DROP TABLE "auth_sessions"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_d95569f623f28a0bf034a55099"`);
        await queryRunner.query(`DROP TABLE "password_resets"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_c90415db608ff4dcd5737ff592"`);
        await queryRunner.query(`DROP TABLE "app_users"`);
        await queryRunner.query(`DROP TYPE "public"."app_users_role_enum"`);
    }

}
