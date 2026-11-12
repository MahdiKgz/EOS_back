import { BadRequestException, ConflictException, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { InjectRepository } from "@nestjs/typeorm";
import { createHmac, randomUUID } from "node:crypto";
import { QueryFailedError, Repository } from "typeorm";
import type { AppUser } from "../users/user.entity";
import { Device } from "./device.entity";
import { DevicesService } from "./devices.service";
import { ACTIVITY_FROM, ACTIVITY_WHERE, activityParameters } from "./backup-activity-query";
import { BackupActivitySelectionDto } from "./device.dto";

type Binding = { id: string; companyId: string | null; name: string; host: string; vendor: string };
type Selection = {
  id: string;
  filters: BackupActivitySelectionDto;
  devices: Binding[];
  eventIds: string[];
  consumedAt: Date | null;
  expired: boolean;
};

@Injectable()
export class BackupActivityService {
  private readonly tokens: JwtService;
  constructor(
    private readonly devicesService: DevicesService,
    @InjectRepository(Device) private readonly devices: Repository<Device>,
    config: ConfigService,
  ) {
    this.tokens = new JwtService({
      secret: createHmac("sha256", config.getOrThrow<string>("JWT_SECRET"))
        .update("backup-global-history-selection")
        .digest(),
      signOptions: { algorithm: "HS256", expiresIn: 300 },
      verifyOptions: { algorithms: ["HS256"] },
    });
  }

  async preview(user: AppUser, input: BackupActivitySelectionDto) {
    const workspace = this.devicesService.managementScope(user);
    return this.devices.manager.transaction(async (manager) => {
      await manager.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
        `backup-activity-selection:${user.id}`,
      ]);
      await manager.query(
        'DELETE FROM "backup_activity_selections" WHERE "expiresAt" < clock_timestamp()',
      );
      const [quota] = await manager.query(
        'SELECT COUNT(*)::integer AS count FROM "backup_activity_selections" WHERE "actorId" = $1 AND "consumedAt" IS NULL',
        [user.id],
      );
      if (quota.count >= 100)
        throw new ConflictException(
          "تعداد انتخاب‌های باز زیاد است. چند دقیقه بعد دوباره تلاش کنید.",
        );
      const [selection] = await manager.query(
        `SELECT COUNT(*)::integer AS count, array_agg(event."id") AS "eventIds",
        COALESCE(jsonb_agg(DISTINCT jsonb_build_object('id', device."id", 'companyId', device."companyId", 'name', device."name", 'host', device."host", 'vendor', device."vendor")), '[]') AS devices
        ${ACTIVITY_FROM} WHERE ${ACTIVITY_WHERE} AND event."action" <> 'history_cleared'`,
        activityParameters(workspace, input),
      );
      if (!selection.count) return { count: 0 };
      const id = randomUUID();
      await manager.query(
        'INSERT INTO "backup_activity_selections" ("id", "actorId", "workspaceOwnerId", "filters", "devices", "eventIds", "count") VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6::bigint[],$7)',
        [
          id,
          user.id,
          workspace,
          JSON.stringify(input),
          JSON.stringify(selection.devices),
          selection.eventIds,
          selection.count,
        ],
      );
      return {
        count: selection.count,
        selectionToken: this.tokens.sign({ id, actor: user.id, workspace }),
      };
    });
  }

  async clear(user: AppUser, token: string) {
    const workspace = this.devicesService.managementScope(user);
    let id: string;
    try {
      const selection = this.tokens.verify<{ id: string; actor: string; workspace: string }>(token);
      if (selection.actor !== user.id || selection.workspace !== workspace) throw new Error();
      id = selection.id;
    } catch {
      throw new BadRequestException(
        "انتخاب تاریخچه معتبر نیست یا منقضی شده است. دوباره انتخاب کنید.",
      );
    }
    try {
      return await this.devices.manager.transaction(async (manager) => {
        await manager.query("SET LOCAL lock_timeout = '5s'");
        const [selection]: Selection[] = await manager.query(
          'SELECT *, "expiresAt" <= clock_timestamp() AS expired FROM "backup_activity_selections" WHERE "id" = $1 AND "actorId" = $2 AND "workspaceOwnerId" = $3 AND "scope" = \'workspace\' FOR UPDATE',
          [id, user.id, workspace],
        );
        if (!selection || selection.expired)
          throw new BadRequestException("انتخاب تاریخچه منقضی شده است. دوباره انتخاب کنید.");
        if (selection.consumedAt) return { deleted: 0 };
        const ids = selection.devices.map((device) => device.id);
        const devices = await manager
          .getRepository(Device)
          .createQueryBuilder("device")
          .withDeleted()
          .where('device."workspaceOwnerId" = :workspace AND device.id = ANY(:ids)', {
            workspace,
            ids,
          })
          .orderBy("device.id", "ASC")
          .setLock("pessimistic_write")
          .getMany();
        const expected = new Map(selection.devices.map((device) => [device.id, device]));
        if (
          devices.length !== ids.length ||
          devices.some((device) => {
            const binding = expected.get(device.id)!;
            return (
              device.deletedAt ||
              device.companyId !== binding.companyId ||
              device.name !== binding.name ||
              device.host !== binding.host ||
              device.vendor !== binding.vendor
            );
          })
        )
          throw new ConflictException(
            "مشخصات، شرکت مالک یا بایگانی تجهیزات تغییر کرده است. تاریخچه را دوباره انتخاب کنید.",
          );
        const [removed]: [{ deviceId: string; id: string }[]] = await manager.query(
          `DELETE FROM "device_backup_events" target
          WHERE target."id" = ANY($1::bigint[]) AND target."deviceId" = ANY($2::text[]) AND target."action" <> 'history_cleared'
          RETURNING target."id"::text AS "id", target."deviceId"`,
          [selection.eventIds, ids],
        );
        if (removed.length) {
          const counts = new Map<string, number>();
          for (const event of removed)
            counts.set(event.deviceId, (counts.get(event.deviceId) ?? 0) + 1);
          await manager.query(
            `INSERT INTO "device_backup_events" ("deviceId", "actorId", "actorName", "actorUsername", "action", "deletedCount", "deviceName", "host", "vendor", "companyName", "occurredAt")
            SELECT device."id", $3, $4, $5, 'history_cleared', removed."count", device."name", device."host", device."vendor", company."name", clock_timestamp()
            FROM jsonb_to_recordset($2::jsonb) AS removed("deviceId" text, "count" integer)
            JOIN "devices" device ON device."id" = removed."deviceId"
            LEFT JOIN "device_companies" company ON company."id" = device."companyId" AND company."workspaceOwnerId" = $1
            WHERE device."workspaceOwnerId" = $1`,
            [
              workspace,
              JSON.stringify([...counts].map(([deviceId, count]) => ({ deviceId, count }))),
              user.id,
              user.displayName,
              user.username,
            ],
          );
        }
        await manager.query(
          'UPDATE "backup_activity_selections" SET "consumedAt" = clock_timestamp(), "deletedCount" = $2, "eventIds" = \'{}\', "devices" = \'[]\', "filters" = \'{}\' WHERE "id" = $1',
          [id, removed.length],
        );
        return { deleted: removed.length };
      });
    } catch (error) {
      if (error instanceof QueryFailedError && ["55P03", "40P01"].includes(error.driverError.code))
        throw new ConflictException("تجهیز یا تاریخچه در حال تغییر است. کمی بعد دوباره تلاش کنید.");
      throw error;
    }
  }
}
