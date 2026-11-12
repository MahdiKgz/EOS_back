import type { MigrationInterface, QueryRunner } from "typeorm";
export class DeviceActionPlans1793702400000 implements MigrationInterface {
  async up(q: QueryRunner): Promise<void> {
    await q.query(`CREATE TABLE device_action_plans (
 id text PRIMARY KEY,"deviceId" text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,"companyId" text,"requestedBy" text NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
 action text NOT NULL,input jsonb NOT NULL,preview jsonb NOT NULL,binding text NOT NULL,"configHash" text NOT NULL,
 status text NOT NULL DEFAULT 'preview' CHECK(status IN ('preview','running','succeeded','failed','verification_failed','verification_pending')),
 "connectorInvoked" boolean NOT NULL DEFAULT false,"errorCode" text,"createdAt" timestamptz NOT NULL DEFAULT now(),"expiresAt" timestamptz NOT NULL,"startedAt" timestamptz,"completedAt" timestamptz
 ); CREATE INDEX "IDX_action_plan_device_recent" ON device_action_plans("deviceId","createdAt");
 CREATE TABLE device_action_events(id text PRIMARY KEY,"deviceId" text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,"companyId" text,"planId" text NOT NULL REFERENCES device_action_plans(id) ON DELETE CASCADE,"actorName" text NOT NULL,action text NOT NULL,"occurredAt" timestamptz NOT NULL DEFAULT now());`);
  }
  async down(): Promise<void> {
    /* Preserve action outcomes and their audit. */
  }
}
