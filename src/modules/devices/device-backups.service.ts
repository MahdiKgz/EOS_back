import {
  BadGatewayException,
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  PayloadTooLargeException,
} from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { createHash, createHmac, randomUUID } from "node:crypto";
import { EntityManager, QueryFailedError, Repository } from "typeorm";
import type { AppUser } from "../users/user.entity";
import { Device } from "./device.entity";
import { DevicesService } from "./devices.service";
import { collectBackup, deviceBackupProfile, sealBackup, unsealBackup } from "./device-backup";
import {
  BackupCatalogQueryDto,
  BackupActivityQueryDto,
  BackupHistoryQueryDto,
  BackupHistorySelectionDto,
} from "./device.dto";
import { ACTIVITY_FROM, ACTIVITY_WHERE, activityParameters } from "./backup-activity-query";
import { sshVaultKey } from "./ssh-credential-vault";
import {
  configIdentity,
  linuxServiceFiles,
  restoreVendor,
  validateRestoreArtifact,
} from "./restore-artifact";

@Injectable()
export class DeviceBackupsService {
  private readonly selections: JwtService;
  private readonly collecting = new Set<string>();
  constructor(
    private readonly devicesService: DevicesService,
    @InjectRepository(Device) private readonly devices: Repository<Device>,
    config: ConfigService,
  ) {
    this.selections = new JwtService({
      secret: createHmac("sha256", config.getOrThrow<string>("JWT_SECRET"))
        .update("backup-history-selection")
        .digest(),
      signOptions: { algorithm: "HS256", expiresIn: 300 },
      verifyOptions: { algorithms: ["HS256"] },
    });
  }

  private async event(
    manager: EntityManager,
    user: AppUser,
    deviceId: string,
    action: string,
    backupId: string | null = null,
    details: {
      device?: Device;
      file?: { filename: string; byteLength: number; sha256: string };
      durationMs?: number;
      deletedCount?: number;
      failureCode?: string;
    } = {},
  ) {
    const device = details.device ?? (await manager.findOneByOrFail(Device, { id: deviceId }));
    const [company] = device.companyId
      ? await manager.query(
          'SELECT "name" FROM "device_companies" WHERE "id" = $1 AND "workspaceOwnerId" = $2',
          [device.companyId, device.workspaceOwnerId],
        )
      : [];
    const file =
      details.file ??
      (backupId
        ? (
            await manager.query(
              'SELECT "filename", "byteLength", "sha256" FROM "device_backups" WHERE "id" = $1 AND "deviceId" = $2',
              [backupId, deviceId],
            )
          )[0]
        : undefined);
    await manager.query(
      `INSERT INTO "device_backup_events" ("deviceId", "backupId", "actorName", "action", "actorId", "deviceName", "host", "vendor", "companyName", "filename", "byteLength", "sha256", "durationMs", "deletedCount", "failureCode", "actorUsername", "occurredAt")
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,clock_timestamp())`,
      [
        deviceId,
        backupId,
        user.displayName,
        action,
        user.id,
        device.name,
        device.host,
        device.vendor,
        company?.name ?? null,
        file?.filename ?? null,
        file?.byteLength ?? null,
        file?.sha256 ?? null,
        details.durationMs ?? null,
        details.deletedCount ?? null,
        details.failureCode ?? null,
        user.username,
      ],
    );
  }

  private async lockedDevice(manager: EntityManager, expected: Device) {
    const id = expected.id;
    const device = await manager.findOne(Device, {
      where: { id, workspaceOwnerId: expected.workspaceOwnerId },
      lock: { mode: "pessimistic_write" },
    });
    if (!device) throw new NotFoundException("تجهیز پیدا نشد.");
    return device;
  }

  async catalog(user: AppUser, query: BackupCatalogQueryDto) {
    const workspace = this.devicesService.managementScope(user);
    const search = query.search ? `%${query.search.replace(/[\\%_]/g, "\\$&")}%` : null;
    const [result] = await this.devices.manager.query(
      `WITH filtered AS (
      SELECT file."id", file."deviceId", file."filename", file."sha256", file."byteLength", file."createdAt", file."origin", file."deviceType",
        device."name" AS "deviceName", device."host", device."companyId", company."name" AS "companyName"
      FROM "device_backups" file JOIN "devices" device ON file."deviceId" = device."id"
      LEFT JOIN "device_companies" company ON company."id" = device."companyId" AND company."workspaceOwnerId" = $1
      WHERE file."workspaceOwnerId" = $1 AND device."workspaceOwnerId" = $1 AND device."deletedAt" IS NULL
      AND file."companyId" IS NOT DISTINCT FROM device."companyId"
      AND ($2::text IS NULL OR device."companyId" = $2)
      AND ($3::text IS NULL OR file."origin" = $3)
      AND ($4::text IS NULL OR file."filename" ILIKE $4 ESCAPE '\\' OR device."name" ILIKE $4 ESCAPE '\\' OR device."host" ILIKE $4 ESCAPE '\\')
    ) SELECT (SELECT COUNT(*) FROM filtered)::integer AS total,
      (SELECT COUNT(DISTINCT "deviceId") FROM filtered)::integer AS "deviceCount",
      (SELECT COALESCE(SUM("byteLength"), 0) FROM filtered)::text AS "totalBytes",
      COALESCE((SELECT json_agg(page ORDER BY page."createdAt" DESC, page."id" DESC) FROM
        (SELECT * FROM filtered ORDER BY "createdAt" DESC, "id" DESC LIMIT 20 OFFSET $5) page), '[]') AS items`,
      [workspace, query.companyId ?? null, query.origin ?? null, search, (query.page - 1) * 20],
    );
    return { ...result, page: query.page, pageSize: 20 };
  }

  async activity(user: AppUser, query: BackupActivityQueryDto) {
    const workspace = this.devicesService.managementScope(user);
    const [result] = await this.devices.manager.query(
      `WITH filtered AS (
      SELECT event."id"::text AS "id", event."deviceId", event."action", event."actorName", event."actorUsername", event."occurredAt",
        COALESCE(event."deviceName", device."name") AS "deviceName", COALESCE(event."host", device."host") AS host,
        COALESCE(event."vendor", device."vendor") AS vendor, COALESCE(event."companyName", company."name") AS "companyName",
        COALESCE(event."filename", file."filename") AS filename, COALESCE(event."byteLength", file."byteLength") AS "byteLength", COALESCE(event."sha256", file."sha256") AS sha256,
        CASE WHEN file."companyId" IS NOT DISTINCT FROM device."companyId" THEN file."id" ELSE NULL END AS "backupId",
        event."durationMs", event."failureCode", event."deletedCount"
      ${ACTIVITY_FROM} WHERE ${ACTIVITY_WHERE}
    ) SELECT (SELECT COUNT(*) FROM filtered)::integer AS total,
      COALESCE((SELECT json_agg(page ORDER BY page."occurredAt" DESC, page."id"::bigint DESC) FROM
        (SELECT * FROM filtered ORDER BY "occurredAt" DESC, "id"::bigint DESC LIMIT 20 OFFSET $6) page), '[]') AS items`,
      [...activityParameters(workspace, query), (query.page - 1) * 20],
    );
    return { ...result, page: query.page, pageSize: 20 };
  }

  async list(
    user: AppUser,
    deviceId: string,
    query: BackupHistoryQueryDto = new BackupHistoryQueryDto(),
  ) {
    const device = await this.devicesService.managedDevice(user, deviceId);
    const files = await this.devices.manager.query(
      `SELECT "id", "filename", "byteLength", "sha256", "createdAt", "origin", "deviceType" FROM "device_backups"
       WHERE "deviceId" = $1 AND "workspaceOwnerId" = $2 AND "companyId" IS NOT DISTINCT FROM $3
       ORDER BY "createdAt" DESC, "id" LIMIT 100`,
      [deviceId, device.workspaceOwnerId, device.companyId],
    );
    const search = query.search ? `%${query.search.replace(/[\\%_]/g, "\\$&")}%` : null;
    const [history] = await this.devices.manager.query(
      `WITH filtered AS (
         SELECT event."id"::text AS "id", event."action", event."actorName", event."occurredAt", event."filename", event."durationMs", event."failureCode", event."deletedCount"
         FROM "device_backup_events" event
         LEFT JOIN "device_backups" file ON event."backupId" = file."id"
         WHERE event."deviceId" = $1
         AND ($2::text IS NULL OR event."action" = $2)
         AND ($3::text IS NULL OR event."actorName" ILIKE $3 ESCAPE '\\' OR COALESCE(event."filename", file."filename") ILIKE $3 ESCAPE '\\')
       )
       SELECT (SELECT COUNT(*) FROM filtered)::integer AS "total",
         COALESCE((SELECT json_agg(page ORDER BY page."occurredAt" DESC, page."id"::bigint DESC)
           FROM (SELECT * FROM filtered ORDER BY "occurredAt" DESC, "id"::bigint DESC LIMIT 20 OFFSET $4) page), '[]') AS events`,
      [deviceId, query.event ?? null, search, (query.page - 1) * 20],
    );
    return {
      profile: deviceBackupProfile(device.type),
      canRestore: ["linux_edge", "cisco", "mikrotik", "fortigate"].includes(device.type),
      canExecuteRestore:
        ["linux_edge", "cisco", "mikrotik", "fortigate"].includes(device.type) &&
        device.protocol === "ssh",
      files,
      events: history.events,
      totalEvents: history.total,
      page: query.page,
      pageSize: 20,
    };
  }

  async previewHistoryClear(user: AppUser, deviceId: string, input: BackupHistorySelectionDto) {
    const device = await this.devicesService.managedDevice(user, deviceId);
    const search = input.search ? `%${input.search.replace(/[\\%_]/g, "\\$&")}%` : null;
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
        `SELECT COUNT(*)::integer AS count, array_agg(event."id") AS "eventIds"
         FROM "device_backup_events" event LEFT JOIN "device_backups" file ON event."backupId" = file."id"
         WHERE event."deviceId" = $1 AND event."action" <> 'history_cleared'
         AND ($2::text IS NULL OR event."action" = $2)
         AND ($3::text IS NULL OR event."actorName" ILIKE $3 ESCAPE '\\' OR COALESCE(event."filename", file."filename") ILIKE $3 ESCAPE '\\')
         AND ($4::bigint IS NULL OR event."id" = $4)`,
        [deviceId, input.event ?? null, search, input.eventId ?? null],
      );
      if (!selection.count) return { count: 0 };
      const selectionId = randomUUID();
      // Exact visible IDs protect even an older, uncommitted INSERT that commits after this preview.
      await manager.query(
        `INSERT INTO "backup_activity_selections" ("id", "actorId", "workspaceOwnerId", "scope", "filters", "devices", "eventIds", "count")
        VALUES ($1,$2,$3,'device',$4::jsonb,$5::jsonb,$6::bigint[],$7)`,
        [
          selectionId,
          user.id,
          device.workspaceOwnerId,
          JSON.stringify(input),
          JSON.stringify([{ id: deviceId, companyId: device.companyId }]),
          selection.eventIds,
          selection.count,
        ],
      );
      return {
        count: selection.count,
        selectionToken: this.selections.sign({
          actor: user.id,
          deviceId,
          workspace: device.workspaceOwnerId,
          companyId: device.companyId,
          selectionId,
        }),
      };
    });
  }

  async clearHistory(user: AppUser, deviceId: string, token: string) {
    const expected = await this.devicesService.managedDevice(user, deviceId);
    let proof: {
      actor: string;
      deviceId: string;
      workspace: string;
      companyId: string | null;
      selectionId: string;
    };
    try {
      proof = this.selections.verify(token);
      if (
        proof.actor !== user.id ||
        proof.deviceId !== deviceId ||
        proof.workspace !== expected.workspaceOwnerId
      )
        throw new Error();
    } catch {
      throw new BadRequestException(
        "انتخاب تاریخچه معتبر نیست یا منقضی شده است. دوباره انتخاب کنید.",
      );
    }
    try {
      return await this.devices.manager.transaction(async (manager) => {
        await manager.query("SET LOCAL lock_timeout = '5s'");
        const [selection] = await manager.query(
          `SELECT "eventIds", "consumedAt", "expiresAt" <= clock_timestamp() AS expired FROM "backup_activity_selections"
          WHERE "id" = $1 AND "actorId" = $2 AND "workspaceOwnerId" = $3 AND "scope" = 'device' FOR UPDATE`,
          [proof.selectionId, user.id, expected.workspaceOwnerId],
        );
        if (!selection || selection.expired)
          throw new BadRequestException("انتخاب تاریخچه منقضی شده است. دوباره انتخاب کنید.");
        const device = await this.lockedDevice(manager, expected);
        if (device.companyId !== proof.companyId)
          throw new ConflictException(
            "شرکت مالک تجهیز تغییر کرده است. تاریخچه را دوباره انتخاب کنید.",
          );
        if (selection.consumedAt) return { deleted: 0 };
        const [removed] = await manager.query(
          `DELETE FROM "device_backup_events" WHERE "deviceId" = $1 AND "id" = ANY($2::bigint[]) AND "action" <> 'history_cleared' RETURNING "id"`,
          [deviceId, selection.eventIds],
        );
        if (removed.length)
          await this.event(manager, user, deviceId, "history_cleared", null, {
            device,
            deletedCount: removed.length,
          });
        await manager.query(
          `UPDATE "backup_activity_selections" SET "consumedAt" = clock_timestamp(), "deletedCount" = $2, "eventIds" = '{}', "devices" = '[]', "filters" = '{}' WHERE "id" = $1`,
          [proof.selectionId, removed.length],
        );
        return { deleted: removed.length };
      });
    } catch (error) {
      if (error instanceof QueryFailedError && ["55P03", "40P01"].includes(error.driverError.code))
        throw new ConflictException("تجهیز یا تاریخچه در حال تغییر است. کمی بعد دوباره تلاش کنید.");
      throw error;
    }
  }

  async create(user: AppUser, deviceId: string) {
    const device = await this.devicesService.managedDevice(user, deviceId);
    if (!deviceBackupProfile(device.type) || device.protocol !== "ssh")
      throw new BadRequestException("کانکتور بک‌آپ برای این نوع تجهیز یا مسیر اتصال آماده نیست.");
    sshVaultKey();
    if (this.collecting.has(deviceId) || this.collecting.size >= 4)
      throw new ConflictException("ظرفیت دریافت بک‌آپ پر است یا این تجهیز در حال دریافت است.");
    this.collecting.add(deviceId);
    const started = performance.now();
    let attemptedDevice = device;
    try {
      return await this.devices.manager.transaction(async (manager) => {
        // Cross-process requests do not collect the same device simultaneously.
        const [lock] = await manager.query(
          "SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0)) AS acquired",
          [`device-backup:${deviceId}`],
        );
        if (!lock.acquired) throw new ConflictException("بک‌آپ این تجهیز در حال دریافت است.");
        const current = await this.lockedDevice(manager, device);
        attemptedDevice = current;
        const credentials = await this.devicesService.savedSshCredentials(user, current, manager);
        const { bytes, filename, sha256 } = await collectBackup(current, credentials);
        const id = randomUUID();
        const [file] = await manager.query(
          `INSERT INTO "device_backups" ("id", "deviceId", "companyId", "workspaceOwnerId", "filename", "sha256", "byteLength", "sealedContent", "deviceType")
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           RETURNING "id", "filename", "sha256", "byteLength", "createdAt", "origin", "deviceType"`,
          [
            id,
            deviceId,
            current.companyId,
            current.workspaceOwnerId,
            filename,
            sha256,
            bytes.length,
            sealBackup(bytes, id, deviceId, current.workspaceOwnerId),
            current.type,
          ],
        );
        await this.event(manager, user, deviceId, "created", id, {
          device: current,
          file,
          durationMs: Math.round(performance.now() - started),
        });
        return file;
      });
    } catch (error) {
      if (!(error instanceof ConflictException))
        await this.event(this.devices.manager, user, deviceId, "failed", null, {
          device: attemptedDevice,
          durationMs: Math.round(performance.now() - started),
          failureCode:
            error instanceof NotFoundException ? "credential_unavailable" : "collection_failed",
        });
      throw error;
    } finally {
      this.collecting.delete(deviceId);
    }
  }

  async upload(user: AppUser, deviceId: string, encodedName: unknown, content: unknown) {
    const expected = await this.devicesService.managedDevice(user, deviceId);
    if (!Buffer.isBuffer(content) || !content.length)
      throw new BadRequestException("فایل بک‌آپ را انتخاب کنید.");
    if (content.length > 20 * 1024 * 1024)
      throw new PayloadTooLargeException("حجم فایل نباید بیشتر از ۲۰ مگابایت باشد.");
    let filename: string;
    try {
      if (typeof encodedName !== "string" || encodedName.length > 1200) throw new Error();
      filename = decodeURIComponent(encodedName)
        .split(/[\\/]/)
        .at(-1)!
        .replace(/[^a-zA-Z0-9_.-]/g, "_")
        .slice(0, 120);
      if (!filename || /^\.+$/.test(filename)) throw new Error();
    } catch {
      throw new BadRequestException("نام فایل بک‌آپ معتبر نیست.");
    }
    const sha256 = createHash("sha256").update(content).digest("hex");
    sshVaultKey();
    return this.devices.manager.transaction(async (manager) => {
      // Serialize the workspace quota across API processes and device uploads.
      await manager.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
        `backup-upload:${expected.workspaceOwnerId}`,
      ]);
      const current = await this.lockedDevice(manager, expected);
      validateRestoreArtifact(restoreVendor(current.type), content);
      const [quota] = await manager.query(
        `SELECT COUNT(*)::integer AS count FROM "device_backups" WHERE "workspaceOwnerId" = $1 AND "origin" = 'uploaded'`,
        [current.workspaceOwnerId],
      );
      if (quota.count >= 100)
        throw new ConflictException(
          "ظرفیت ۱۰۰ فایل آپلودشده پر شده است. فایل‌های غیرضروری را حذف کنید.",
        );
      const id = randomUUID();
      const [file] = await manager.query(
        `INSERT INTO "device_backups" ("id", "deviceId", "companyId", "workspaceOwnerId", "filename", "sha256", "byteLength", "sealedContent", "deviceType", "origin")
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'uploaded') RETURNING "id", "filename", "sha256", "byteLength", "createdAt", "origin", "deviceType"`,
        [
          id,
          deviceId,
          current.companyId,
          current.workspaceOwnerId,
          filename,
          sha256,
          content.length,
          sealBackup(content, id, deviceId, current.workspaceOwnerId),
          current.type,
        ],
      );
      await this.event(manager, user, deviceId, "uploaded", id, { device: current, file });
      return file;
    });
  }

  async readArtifact(manager: EntityManager, device: Device, backupId: string) {
    const [file] = await manager.query(
      `SELECT * FROM "device_backups" WHERE "id" = $1 AND "deviceId" = $2
       AND "workspaceOwnerId" = $3 AND "companyId" IS NOT DISTINCT FROM $4`,
      [backupId, device.id, device.workspaceOwnerId, device.companyId],
    );
    if (!file) throw new NotFoundException("فایل بک‌آپ پیدا نشد.");
    let content: Buffer;
    try {
      content = unsealBackup(file.sealedContent, file.id, device.id, device.workspaceOwnerId);
      if (
        content.length !== file.byteLength ||
        createHash("sha256").update(content).digest("hex") !== file.sha256
      )
        throw new Error();
    } catch {
      throw new BadGatewayException(
        "فایل بک‌آپ قابل اعتبارسنجی نیست. کلید رمزنگاری را بررسی کنید.",
      );
    }
    return {
      file: {
        id: String(file.id),
        filename: String(file.filename),
        sha256: String(file.sha256),
        byteLength: Number(file.byteLength),
        deviceType: String(file.deviceType),
        origin: String(file.origin),
        createdAt: file.createdAt as Date,
      },
      content,
    };
  }

  async review(user: AppUser, deviceId: string, backupId: string) {
    const expected = await this.devicesService.managedDevice(user, deviceId);
    return this.devices.manager.transaction(async (manager) => {
      const device = await this.lockedDevice(manager, expected);
      const { file, content } = await this.readArtifact(manager, device, backupId);
      if (file.deviceType !== device.type)
        throw new ConflictException("نوع تجهیز از زمان ثبت فایل تغییر کرده است.");
      const vendor = restoreVendor(device.type);
      validateRestoreArtifact(vendor, content);
      return {
        ...file,
        vendor,
        identity: configIdentity(vendor, content),
        files:
          vendor === "linux"
            ? linuxServiceFiles(content, true).map(({ path, bytes, sha256, kind }) => ({
                path,
                bytes,
                sha256,
                kind,
              }))
            : [],
      };
    });
  }

  async download(user: AppUser, deviceId: string, backupId: string) {
    const device = await this.devicesService.managedDevice(user, deviceId);
    return this.devices.manager.transaction(async (manager) => {
      const current = await this.lockedDevice(manager, device);
      const { file, content } = await this.readArtifact(manager, current, backupId);
      await this.event(manager, user, deviceId, "downloaded", backupId, { device: current, file });
      return { filename: file.filename, sha256: file.sha256, content: content.toString("base64") };
    });
  }

  async deleteFile(user: AppUser, deviceId: string, backupId: string) {
    const device = await this.devicesService.managedDevice(user, deviceId);
    return this.devices.manager.transaction(async (manager) => {
      const current = await this.lockedDevice(manager, device);
      const [rows] = await manager.query(
        `DELETE FROM "device_backups" WHERE "id" = $1 AND "deviceId" = $2
         AND "workspaceOwnerId" = $3 AND "companyId" IS NOT DISTINCT FROM $4 RETURNING "id", "filename", "byteLength", "sha256"`,
        [backupId, deviceId, current.workspaceOwnerId, current.companyId],
      );
      if (!rows.length) throw new NotFoundException("فایل بک‌آپ پیدا نشد.");
      await this.event(manager, user, deviceId, "file_deleted", backupId, {
        device: current,
        file: rows[0],
      });
      return { deleted: true };
    });
  }
}
