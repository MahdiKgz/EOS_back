import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { createHash, randomUUID } from "node:crypto";
import { EntityManager, QueryFailedError, Repository } from "typeorm";
import { AppUser } from "../users/user.entity";
import { Device } from "./device.entity";
import { DeviceBackupsService } from "./device-backups.service";
import { DevicesService } from "./devices.service";
import { collectBackup } from "./device-backup";
import {
  assertCompatible,
  validateRestoreArtifact,
  restoreVendor,
  RESTORE_TEMPLATES,
  type RestoreVendor,
} from "./restore-artifact";
import { preflightRestore, applyRestore, verifyRestoredConfiguration } from "./native-restore";
import type { ExecuteDeviceRestoreDto } from "./device.dto";

type Plan = {
  id: string;
  artifactId: string;
  deviceId: string;
  requestedBy: string;
  binding: string;
  sha256: string;
  filename: string;
  companyId: string | null;
  expiresAt: Date;
  status: string;
  vendor: RestoreVendor;
  connectorInvoked: boolean;
  state: string;
  heartbeatAt: Date | null;
  startedAt: Date | null;
};

@Injectable()
export class DeviceRestoresService {
  private readonly logger = new Logger(DeviceRestoresService.name);
  private readonly previews = new Set<string>();
  constructor(
    private readonly devicesService: DevicesService,
    private readonly backups: DeviceBackupsService,
    @InjectRepository(Device) private readonly devices: Repository<Device>,
  ) {}

  private async transaction<T>(work: (manager: EntityManager) => Promise<T>) {
    try {
      return await this.devices.manager.transaction(work);
    } catch (error) {
      if (error instanceof QueryFailedError && ["55P03", "40P01"].includes(error.driverError.code))
        throw new ConflictException(
          "عملیات دیگری روی تجهیز یا اعتبارنامه در حال اجرا است. کمی بعد دوباره تلاش کنید.",
        );
      throw error;
    }
  }

  private async binding(manager: EntityManager, device: Device) {
    const [secret] = await manager.query(
      `SELECT COALESCE(profile."sealedCredentials", credential."sealedCredentials", '') AS credential,
      access."compatibilityProfile", access.revision AS "ciscoRevision", enable."sealedSecret" AS "enableSecret"
      FROM "devices" device LEFT JOIN "device_ssh_profiles" profile ON profile."deviceId" = device."id"
      LEFT JOIN "device_credentials" credential ON credential."id" = device."credentialId"
      LEFT JOIN device_cisco_access access ON access."deviceId"=device.id
      LEFT JOIN cisco_enable_credentials enable ON enable.id=access."enableCredentialId"
      WHERE device."id" = $1`,
      [device.id],
    );
    return createHash("sha256")
      .update(
        JSON.stringify([
          device.id,
          device.workspaceOwnerId,
          device.companyId,
          device.type,
          device.vendor,
          device.host,
          device.managementPort,
          device.protocol,
          device.accessRoute,
          device.credentialId,
          secret.credential,
          secret.compatibilityProfile,
          secret.ciscoRevision,
          secret.enableSecret,
        ]),
      )
      .digest("hex");
  }

  private async lockedDevice(manager: EntityManager, expected: Device) {
    const device = await manager.findOne(Device, {
      where: { id: expected.id, workspaceOwnerId: expected.workspaceOwnerId },
      lock: { mode: "pessimistic_write" },
    });
    if (!device) throw new NotFoundException("تجهیز پیدا نشد.");
    restoreVendor(device.type);
    if (device.protocol !== "ssh")
      throw new BadRequestException("بازیابی به اتصال SSH تجهیز نیاز دارد.");
    if (device.credentialId) {
      // Fail before any write if a credential editor already owns this row. NOWAIT avoids a trigger/device-lock deadlock.
      try {
        await manager.query(
          'SELECT "id" FROM "device_credentials" WHERE "id" = $1 FOR SHARE NOWAIT',
          [device.credentialId],
        );
      } catch {
        throw new ConflictException(
          "اعتبارنامه در حال تغییر است. پس از پایان ویرایش دوباره تلاش کنید.",
        );
      }
    }
    return device;
  }

  private async event(manager: EntityManager, planId: string, actorName: string, action: string) {
    await manager.query(
      'INSERT INTO "device_restore_events" ("planId", "actorName", "action", "occurredAt") VALUES ($1,$2,$3,clock_timestamp())',
      [planId, actorName, action],
    );
  }

  async list(user: AppUser, deviceId: string) {
    const device = await this.devicesService.managedDevice(user, deviceId);
    const items = await this.devices.manager.query(
      `SELECT "id", "filename", "sha256", "actorName", "vendor", "status", "state", "connectorInvoked", "safetyBackupId", "createdAt", "expiresAt", "startedAt", "finishedAt",
      ("status" = 'running' AND COALESCE("heartbeatAt", "startedAt") < now() - interval '10 minutes') AS interrupted,
      ("status" = 'ready' AND "expiresAt" < now()) AS expired
      FROM "device_restore_plans" WHERE "deviceId" = $1 AND "workspaceOwnerId" = $2 AND "companyId" IS NOT DISTINCT FROM $3 ORDER BY "createdAt" DESC, "id" DESC LIMIT 50`,
      [deviceId, device.workspaceOwnerId, device.companyId],
    );
    return { items };
  }

  async preview(user: AppUser, deviceId: string, artifactId: string) {
    const expected = await this.devicesService.managedDevice(user, deviceId);
    if (this.previews.size >= 4 || this.previews.has(deviceId))
      throw new ConflictException("بررسی بازیابی این تجهیز یا ظرفیت بررسی‌ها مشغول است.");
    this.previews.add(deviceId);
    try {
      return await this.transaction(async (manager) => {
        await manager.query("SET LOCAL lock_timeout = '5s'");
        const device = await this.lockedDevice(manager, expected);
        const { file, content } = await this.backups.readArtifact(manager, device, artifactId);
        if (file.deviceType !== device.type)
          throw new ConflictException("نوع تجهیز با فایل بازیابی تطابق ندارد.");
        const vendor = restoreVendor(device.type);
        validateRestoreArtifact(vendor, content);
        const credentials = await this.devicesService.savedSshCredentials(user, device, manager);
        const current = await collectBackup(device, credentials);
        assertCompatible(vendor, content, current.bytes);
        await preflightRestore(device, credentials, vendor, content);
        const id = randomUUID();
        const [plan] = await manager.query(
          `INSERT INTO "device_restore_plans" ("id", "deviceId", "requestedBy", "workspaceOwnerId", "companyId", "artifactId", "filename", "sha256", "binding", "actorName", "vendor", "createdAt", "expiresAt")
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp(),clock_timestamp()+interval '10 minutes') RETURNING "id", "filename", "sha256", "expiresAt"`,
          [
            id,
            deviceId,
            user.id,
            device.workspaceOwnerId,
            device.companyId,
            artifactId,
            file.filename,
            file.sha256,
            await this.binding(manager, device),
            user.displayName,
            vendor,
          ],
        );
        await this.event(manager, id, user.displayName, "preview");
        return {
          ...plan,
          deviceName: device.name,
          host: device.host,
          vendor,
          method: RESTORE_TEMPLATES[vendor].method,
          connectorInvoked: false,
        };
      });
    } finally {
      this.previews.delete(deviceId);
    }
  }

  private async checkPlan(
    manager: EntityManager,
    device: Device,
    plan: Plan,
    allowExpired = false,
  ) {
    if (!allowExpired && Date.now() >= new Date(plan.expiresAt).getTime())
      throw new ConflictException("پیش‌نمایش بازیابی منقضی شده است. دوباره بررسی کنید.");
    if (
      device.companyId !== plan.companyId ||
      restoreVendor(device.type) !== plan.vendor ||
      (await this.binding(manager, device)) !== plan.binding
    )
      throw new ConflictException("مقصد یا اعتبارنامه تغییر کرده است. پیش‌نمایش جدید بسازید.");
    const artifact = await this.backups.readArtifact(manager, device, plan.artifactId);
    if (artifact.file.sha256 !== plan.sha256 || artifact.file.deviceType !== device.type)
      throw new ConflictException("فایل بازیابی تغییر کرده است.");
    validateRestoreArtifact(plan.vendor, artifact.content);
    return artifact;
  }

  async execute(user: AppUser, deviceId: string, id: string, input: ExecuteDeviceRestoreDto) {
    const expected = await this.devicesService.managedDevice(user, deviceId);
    await this.transaction(async (manager) => {
      await manager.query("SET LOCAL lock_timeout = '5s'");
      await manager.query(
        "SELECT pg_advisory_xact_lock(hashtextextended('device-restore-claims', 0))",
      );
      const device = await this.lockedDevice(manager, expected);
      const [plan]: Plan[] = await manager.query(
        'SELECT * FROM "device_restore_plans" WHERE "id" = $1 AND "deviceId" = $2 AND "requestedBy" = $3 FOR UPDATE',
        [id, deviceId, user.id],
      );
      if (!plan) throw new NotFoundException("برنامهٔ بازیابی پیدا نشد.");
      if (plan.status !== "ready")
        throw new ConflictException(
          "این برنامه قبلاً اجرا شده است. برای اجرای جدید پیش‌نمایش بسازید.",
        );
      if (input.sha256 !== plan.sha256)
        throw new ConflictException("فایل تأییدشده با برنامهٔ بازیابی تطابق ندارد.");
      if (
        input.intent !== "execute" ||
        input.confirmation !== "RESTORE BACKUP" ||
        (plan.vendor === "linux" && input.fullEtcConfirmation !== "RESTORE FULL ETC")
      )
        throw new BadRequestException("تأیید بازیابی کامل نیست.");
      await this.checkPlan(manager, device, plan);
      const [active] = await manager.query(
        `SELECT COUNT(*)::integer AS count, COALESCE(bool_or("deviceId" = $1), false) AS same FROM "device_restore_plans" WHERE "status" = 'running' AND COALESCE("heartbeatAt", "startedAt") > now() - interval '10 minutes'`,
        [deviceId],
      );
      if (active.count >= 4 || active.same)
        throw new ConflictException("بازیابی این تجهیز یا ظرفیت اجرا مشغول است.");
      await manager.query(
        'UPDATE "device_restore_plans" SET "status" = \'running\', "state" = \'taking_safety_backup\', "startedAt" = now(), "heartbeatAt" = now() WHERE "id" = $1',
        [id],
      );
      await this.event(manager, id, user.displayName, "confirmed");
    });
    void this.run(user.id, expected, id).catch(() =>
      this.logger.error(`Restore outcome could not be recorded for plan ${id}`),
    );
    return { id, status: "running", state: "taking_safety_backup" };
  }

  private async run(userId: string, expected: Device, id: string) {
    let connectorInvoked = false;
    let safetyBackupId: string | null = null;
    let updatingHeartbeat = false;
    const heartbeat = setInterval(() => {
      if (updatingHeartbeat) return;
      updatingHeartbeat = true;
      void this.devices.manager
        .query(
          'UPDATE "device_restore_plans" SET "heartbeatAt" = now() WHERE "id" = $1 AND "status" = \'running\'',
          [id],
        )
        .catch(() => undefined)
        .finally(() => {
          updatingHeartbeat = false;
        });
    }, 30000);
    heartbeat.unref();
    try {
      const actor = await this.devices.manager.findOneBy(AppUser, { id: userId, isActive: true });
      if (!actor || this.devicesService.managementScope(actor) !== expected.workspaceOwnerId)
        throw new ForbiddenException();
      // This backup commits independently before applying anything to the remote host.
      const safety = await this.backups.create(actor, expected.id);
      safetyBackupId = safety.id;
      await this.devices.manager.query(
        'UPDATE "device_restore_plans" SET "safetyBackupId" = $2 WHERE "id" = $1',
        [id, safetyBackupId],
      );
      await this.event(this.devices.manager, id, actor.displayName, "safety_backup");
      const outcome = await this.transaction(async (manager) => {
        await manager.query("SET LOCAL lock_timeout = '5s'");
        const currentActor = await manager.findOne(AppUser, {
          where: { id: userId, isActive: true },
          lock: { mode: "pessimistic_read" },
        });
        if (
          !currentActor ||
          this.devicesService.managementScope(currentActor) !== expected.workspaceOwnerId
        )
          throw new ForbiddenException();
        const [lock] = await manager.query(
          "SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0)) AS acquired",
          [`device-backup:${expected.id}`],
        );
        if (!lock.acquired) throw new ConflictException();
        const device = await this.lockedDevice(manager, expected);
        const [plan]: Plan[] = await manager.query(
          'SELECT * FROM "device_restore_plans" WHERE "id" = $1 AND "status" = \'running\'',
          [id],
        );
        if (!plan) throw new ConflictException();
        const artifact = await this.checkPlan(manager, device, plan);
        const safetyArtifact = await this.backups.readArtifact(manager, device, safety.id);
        assertCompatible(plan.vendor, artifact.content, safetyArtifact.content);
        const credentials = await this.devicesService.savedSshCredentials(
          currentActor,
          device,
          manager,
        );
        await preflightRestore(device, credentials, plan.vendor, artifact.content);
        await this.checkPlan(manager, device, plan);
        // Commit the invocation marker before starting the external write, so a crash cannot be shown as a harmless preview.
        await this.devices.manager.query(
          'UPDATE "device_restore_plans" SET "connectorInvoked" = true, "state" = \'applying\' WHERE "id" = $1',
          [id],
        );
        await this.event(this.devices.manager, id, actor.displayName, "apply_started");
        connectorInvoked = true;
        return applyRestore(device, credentials, plan.vendor, artifact.content);
      });
      await this.finish(id, outcome.verified, outcome.state, true);
    } catch {
      await this.finish(
        id,
        false,
        connectorInvoked ? "needs_review" : "failed_before_apply",
        connectorInvoked,
      );
    } finally {
      clearInterval(heartbeat);
    }
  }

  async verify(user: AppUser, deviceId: string, id: string) {
    const expected = await this.devicesService.managedDevice(user, deviceId);
    return this.transaction(async (manager) => {
      await manager.query("SET LOCAL lock_timeout = '5s'");
      const device = await this.lockedDevice(manager, expected);
      const [plan]: Plan[] = await manager.query(
        'SELECT * FROM "device_restore_plans" WHERE "id" = $1 AND "deviceId" = $2 AND "requestedBy" = $3 FOR UPDATE',
        [id, deviceId, user.id],
      );
      if (!plan) throw new NotFoundException("برنامهٔ بازیابی پیدا نشد.");
      const lastHeartbeat = plan.heartbeatAt ?? plan.startedAt;
      const interrupted =
        plan.status === "running" &&
        !!lastHeartbeat &&
        Date.now() - new Date(lastHeartbeat).getTime() > 10 * 60000;
      if (
        !plan.connectorInvoked ||
        ![
          "awaiting_verification",
          "applied_merge_needs_review",
          "needs_review",
          ...(interrupted ? ["applying"] : []),
        ].includes(plan.state) ||
        (plan.status === "running" && !interrupted) ||
        plan.status === "succeeded"
      )
        throw new ConflictException(
          "این عملیات به بررسی مجدد نتیجه نیاز ندارد یا هنوز در حال اجرا است.",
        );
      const artifact = await this.checkPlan(manager, device, plan, true);
      const credentials = await this.devicesService.savedSshCredentials(user, device, manager);
      if (!(await verifyRestoredConfiguration(device, credentials, plan.vendor, artifact.content)))
        throw new ConflictException(
          "تنظیمات فعلی هنوز با فایل بازیابی تطابق ندارد. وضعیت تجهیز را بررسی کنید.",
        );
      const state =
        plan.vendor === "linux"
          ? "files_verified_activation_required"
          : plan.vendor === "cisco"
            ? "running_configuration_verified"
            : "configuration_verified";
      await this.event(manager, id, user.displayName, "verified");
      await this.finish(id, true, state, true, manager);
      return { id, verified: true, state };
    });
  }

  private async finish(
    id: string,
    success: boolean,
    state: string,
    connectorInvoked: boolean,
    manager?: EntityManager,
  ) {
    const write = async (manager: EntityManager) => {
      const [rows] = await manager.query(
        'UPDATE "device_restore_plans" SET "status" = $2, "state" = $3, "connectorInvoked" = $4, "finishedAt" = clock_timestamp() WHERE "id" = $1 RETURNING "actorName"',
        [id, success ? "succeeded" : "failed", state, connectorInvoked],
      );
      const plan = rows[0];
      if (plan) await this.event(manager, id, plan.actorName, "result");
    };
    if (manager) await write(manager);
    else await this.transaction(write);
  }
}
