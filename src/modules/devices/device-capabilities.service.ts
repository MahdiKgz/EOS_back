import { collectFortiInventory, type FortiInventory } from "./fortigate-collector";
import { ciscoAccessCode, ciscoAccessMessages } from "./cisco-access-error";
import {
  BadGatewayException,
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from "@nestjs/common";
import { createHmac, randomUUID } from "node:crypto";
import { DataSource, EntityManager } from "typeorm";
import { AppUser } from "../users/user.entity";
import { Device } from "./device.entity";
import { DeviceCapabilityCache } from "./device-capability.entity";
import { DevicesService } from "./devices.service";
import { collectCiscoInventory, type CiscoInventory } from "./cisco-collector";
import { sshVaultKey } from "./ssh-credential-vault";
@Injectable()
export class DeviceCapabilitiesService {
  private readonly running = new Set<string>();
  constructor(
    private readonly db: DataSource,
    private readonly devices: DevicesService,
  ) {}
  private async actor(manager: EntityManager, user: AppUser, lock = false) {
    const current = await manager.findOne(AppUser, {
      where: { id: user.id },
      ...(lock ? { lock: { mode: "pessimistic_read" as const } } : {}),
    });
    if (
      !current?.isActive ||
      this.devices.managementScope(current) !== (user.workspaceOwnerId ?? user.id)
    )
      throw new ForbiddenException("دسترسی به تجهیز تغییر کرده است.");
    return current;
  }
  private async parent(manager: EntityManager, user: AppUser, id: string, lock = false) {
    const device = await manager.findOne(Device, {
      where: { id, workspaceOwnerId: user.workspaceOwnerId ?? user.id },
      ...(lock ? { lock: { mode: "pessimistic_write" as const } } : {}),
    });
    if (!device) throw new NotFoundException("تجهیز فعال پیدا نشد.");
    if (!["cisco", "fortigate"].includes(device.type) || device.protocol !== "ssh")
      throw new BadRequestException(
        "کشف قابلیت در این مسیر به Cisco یا FortiGate با اتصال SSH نیاز دارد.",
      );
    return device;
  }
  private async credential(manager: EntityManager, user: AppUser, device: Device, lock = false) {
    const stored = await this.devices.savedSshCredentialSnapshot(user, device, manager, lock);
    const binding = createHmac("sha256", sshVaultKey())
      .update(
        JSON.stringify([
          `${device.type}-capabilities-v1`,
          device.id,
          device.workspaceOwnerId,
          device.companyId,
          device.host,
          device.managementPort,
          device.protocol,
          device.type,
          device.vendor,
          stored.revision,
        ]),
      )
      .digest("hex");
    return { ...stored, binding };
  }
  private cache(manager: EntityManager, id: string) {
    return manager
      .getRepository(DeviceCapabilityCache)
      .createQueryBuilder("cache")
      .addSelect(["cache.binding", "cache.leaseToken", "cache.leaseExpiresAt"])
      .where("cache.deviceId=:id", { id })
      .getOne();
  }
  async report(user: AppUser, id: string) {
    const device = await this.devices.get(user, id);
    if (!["cisco", "fortigate"].includes(device.type) || device.protocol !== "ssh")
      throw new BadRequestException("کشف قابلیت در این مسیر برای Cisco و FortiGate با SSH است.");
    const cache = await this.cache(this.db.manager, id);
    let valid = false;
    if (cache?.snapshot && cache.companyId === device.companyId && cache.actorId) {
      try {
        const actor = await this.db.getRepository(AppUser).findOneBy({ id: cache.actorId });
        if (actor?.isActive && this.devices.managementScope(actor) === device.workspaceOwnerId)
          valid = (await this.credential(this.db.manager, actor, device)).binding === cache.binding;
      } catch {
        /* A removed/revoked private credential cannot validate cached readiness. */
      }
    }
    const latest =
      cache?.companyId === device.companyId && cache.snapshot?.detection.vendor === device.type
        ? cache.snapshot
        : null;
    const stale =
      !valid || !cache?.expiresAt || cache.expiresAt < new Date() || !!cache.lastErrorCode;
    const history = await this.db.query(
      `SELECT "id","actorName","status","platform","startedAt","completedAt","errorCode","commandCount" FROM "device_capability_runs" WHERE "deviceId"=$1 AND "companyId" IS NOT DISTINCT FROM $2 AND "completedAt">now()-interval '30 days' ORDER BY "completedAt" DESC,"id" DESC LIMIT 50`,
      [id, device.companyId],
    );
    return {
      companyId: device.companyId,
      latest,
      stale,
      ready: !stale && !!latest?.detection.supported,
      running: !!cache?.leaseExpiresAt && cache.leaseExpiresAt > new Date(),
      lastAttemptAt: cache?.lastAttemptAt ?? null,
      lastErrorCode: cache?.lastErrorCode ?? null,
      expiresAt: latest ? (cache?.expiresAt ?? null) : null,
      history,
    };
  }
  async refresh(user: AppUser, id: string) {
    if (this.running.has(id))
      throw new ConflictException("گردآوری قابلیت‌های این تجهیز در حال اجراست.");
    if (this.running.size >= 4)
      throw new ServiceUnavailableException("ظرفیت گردآوری پر است. کمی بعد تلاش کنید.");
    this.running.add(id);
    const token = randomUUID(),
      startedAt = new Date();
    let captured: Awaited<ReturnType<DeviceCapabilitiesService["credential"]>> | undefined,
      target: Device | undefined;
    try {
      await this.db.transaction(async (manager) => {
        const actor = await this.actor(manager, user, true),
          device = await this.parent(manager, actor, id, true);
        await manager
          .createQueryBuilder()
          .insert()
          .into(DeviceCapabilityCache)
          .values({ deviceId: id })
          .orIgnore()
          .execute();
        const cache = await this.cache(manager, id);
        if (cache?.leaseExpiresAt && cache.leaseExpiresAt > new Date())
          throw new ConflictException("گردآوری قابلیت‌های این تجهیز در حال اجراست.");
        captured = await this.credential(manager, actor, device, true);
        target = device;
        await manager.update(
          DeviceCapabilityCache,
          { deviceId: id },
          {
            leaseToken: token,
            leaseExpiresAt: new Date(Date.now() + 90000),
            lastAttemptAt: startedAt,
          },
        );
      });
      let inventory: CiscoInventory | FortiInventory | undefined;
      let failure = "CISCO_CONNECTION_FAILED";
      try {
        inventory =
          target!.type === "fortigate"
            ? await collectFortiInventory(target!, captured!.credentials)
            : await collectCiscoInventory(target!, captured!.credentials);
      } catch (error) {
        failure =
          target!.type === "fortigate" ? "FORTIGATE_CONNECTION_FAILED" : ciscoAccessCode(error);
      }
      const completedAt = new Date();
      await this.db.transaction(async (manager) => {
        const actor = await this.actor(manager, user, true),
          current = await this.parent(manager, actor, id, true),
          cache = await this.cache(manager, id);
        if (
          cache?.leaseToken !== token ||
          !cache.leaseExpiresAt ||
          cache.leaseExpiresAt < completedAt
        )
          throw new ConflictException("گردآوری با تغییر تجهیز یا بایگانی بی‌اعتبار شد.");
        let credential: Awaited<ReturnType<DeviceCapabilitiesService["credential"]>>;
        try {
          credential = await this.credential(manager, actor, current, true);
        } catch {
          throw new ConflictException("اعتبارنامه هنگام گردآوری تغییر کرد.");
        }
        if (credential.binding !== captured!.binding)
          throw new ConflictException("تجهیز یا اعتبارنامه حین گردآوری تغییر کرد. نتیجه ثبت نشد.");
        if (inventory) {
          await manager.update(
            DeviceCapabilityCache,
            { deviceId: id },
            {
              actorId: actor.id,
              companyId: current.companyId,
              binding: credential.binding,
              snapshot: {
                ...inventory,
                source: { host: current.host, port: current.managementPort },
              },
              collectedAt: new Date(inventory.collectedAt),
              expiresAt: new Date(+completedAt + 300000),
              lastErrorCode: null,
            },
          );
          current.verification = inventory.detection.supported
            ? {
                checkedAt: inventory.collectedAt,
                identity: {
                  Manufacturer: current.type === "fortigate" ? "Fortinet" : "Cisco",
                  FirmwareVersion: inventory.detection.version ?? "",
                  PlatformFamily: inventory.detection.platform,
                },
              }
            : null;
          await manager.save(current);
        } else
          await manager.update(DeviceCapabilityCache, { deviceId: id }, { lastErrorCode: failure });
        const status = !inventory
          ? "failed"
          : !inventory.detection.supported
            ? "unsupported"
            : inventory.collection?.inventoryStatus === "collected" && !inventory.warnings.length
              ? "collected"
              : "partial";
        await manager.query(
          `INSERT INTO device_capability_runs (id,"deviceId","companyId","actorName",status,platform,"startedAt","completedAt","errorCode","commandCount") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [
            randomUUID(),
            id,
            current.companyId,
            actor.displayName,
            status,
            inventory?.detection.platform ?? null,
            startedAt,
            completedAt,
            inventory ? null : failure,
            inventory?.collection?.commandEvidence.filter((c) => c.state === "collected").length ??
              0,
          ],
        );
        await manager.query(
          `DELETE FROM device_capability_runs WHERE "deviceId"=$1 AND ("completedAt"<now()-interval '30 days' OR id NOT IN (SELECT id FROM device_capability_runs WHERE "deviceId"=$1 ORDER BY "completedAt" DESC,id DESC LIMIT 50))`,
          [id],
        );
      });
      if (!inventory)
        throw new BadGatewayException({
          message:
            ciscoAccessMessages[failure] ??
            "گردآوری FortiGate انجام نشد. آدرس، کلید میزبان، اعتبارنامه و مجوز خواندن وضعیت را بررسی کنید.",
          code: failure,
        });
      return {
        deviceId: id,
        collectedAt: inventory.collectedAt,
        supported: inventory.detection.supported,
        warnings: inventory.warnings,
      };
    } finally {
      this.running.delete(id);
      await this.db
        .createQueryBuilder()
        .update(DeviceCapabilityCache)
        .set({ leaseToken: null, leaseExpiresAt: null })
        .where('"deviceId"=:id AND "leaseToken"=:token', { id, token })
        .execute();
    }
  }
}
