import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import { createHmac, randomUUID } from "node:crypto";
import { DataSource, EntityManager, QueryFailedError } from "typeorm";
import { AppUser, AppUserRole } from "../users/user.entity";
import { Device } from "./device.entity";
import { CiscoEnableCredential, DeviceCiscoAccess } from "./cisco-access.entity";
import {
  CiscoRegistrationOptions,
  SaveCiscoAccessDto,
  SaveEnableCredentialDto,
} from "./cisco-access.dto";
import { sealCiscoEnable, unsealCiscoEnable, sshVaultKey } from "./ssh-credential-vault";
import type { SshCredentials } from "./linux-ssh";
@Injectable()
export class CiscoAccessService {
  constructor(private readonly db: DataSource) {}
  private async transaction<T>(work: (manager: EntityManager) => Promise<T>) {
    try {
      return await this.db.transaction(work);
    } catch (error) {
      if (
        error instanceof QueryFailedError &&
        ["40P01", "55P03", "40001"].includes(error.driverError.code)
      )
        throw new ConflictException(
          "تجهیز یا اعتبارنامه هم‌زمان در حال تغییر است. دوباره تلاش کنید.",
        );
      throw error;
    }
  }
  private scope(user: AppUser) {
    if (user.allowedSections.length && !user.allowedSections.includes("assets"))
      throw new ForbiddenException("به دارایی‌ها دسترسی ندارید.");
    return user.workspaceOwnerId ?? user.id;
  }
  private assertDevice(device: Pick<Device, "type" | "protocol">) {
    if (device.type !== "cisco" || device.protocol !== "ssh")
      throw new BadRequestException("این تنظیمات فقط برای اتصال SSH در Cisco هستند.");
  }
  async credentials(user: AppUser) {
    this.scope(user);
    return this.db.getRepository(CiscoEnableCredential).find({
      where: { ownerId: user.id },
      order: { name: "ASC" },
      select: { id: true, name: true },
    });
  }
  private async owned(manager: EntityManager, user: AppUser, id: string, lock = false) {
    this.scope(user);
    const record = await manager.findOne(CiscoEnableCredential, {
      where: { id, ownerId: user.id },
      select: { id: true, sealedSecret: true },
      ...(lock ? { lock: { mode: "pessimistic_read" as const } } : {}),
    });
    if (!record)
      throw new NotFoundException(
        "اعتبارنامهٔ enable در حساب شما پیدا نشد. موردی از اعتبارنامه‌های خودتان انتخاب کنید.",
      );
    return record;
  }
  private async invalidate(manager: EntityManager, ids: string[]) {
    if (!ids.length) return;
    await manager.query(`UPDATE devices SET verification=NULL WHERE id=ANY($1::text[])`, [ids]);
    await manager.query(
      `UPDATE device_capability_cache SET binding=NULL,"expiresAt"=NULL,"leaseToken"=NULL,"leaseExpiresAt"=NULL WHERE "deviceId"=ANY($1::text[])`,
      [ids],
    );
    await manager.query(
      `UPDATE device_monitoring SET enabled=false,"nextRunAt"=NULL,"leaseToken"=NULL,"leaseExpiresAt"=NULL,"revision"=$2,"lastErrorCode"='MONITOR_CONFIGURATION_INVALID' WHERE "deviceId"=ANY($1::text[])`,
      [ids, randomUUID()],
    );
  }
  private async event(manager: EntityManager, user: AppUser, ids: string[], action: string) {
    if (!ids.length) return;
    await manager.query(
      `INSERT INTO device_cisco_access_events (id,"deviceId","companyId","actorName",action,"compatibilityProfile","enableConfigured")
      SELECT gen_random_uuid()::text,d.id,d."companyId",$2,$3,c."compatibilityProfile",c."enableCredentialId" IS NOT NULL
      FROM devices d JOIN device_cisco_access c ON c."deviceId"=d.id WHERE d.id=ANY($1::text[])`,
      [ids, user.displayName, action],
    );
    await manager.query(
      `DELETE FROM device_cisco_access_events e WHERE "deviceId"=ANY($1::text[]) AND ("occurredAt"<now()-interval '30 days' OR id NOT IN
      (SELECT id FROM device_cisco_access_events WHERE "deviceId"=e."deviceId" ORDER BY "occurredAt" DESC,id DESC LIMIT 50))`,
      [ids],
    );
  }
  async saveCredential(user: AppUser, input: SaveEnableCredentialDto, id?: string) {
    this.scope(user);
    if (id) await this.owned(this.db.manager, user, id);
    const recordId = id ?? randomUUID();
    await this.transaction(async (manager) => {
      if (id) {
        const parents: { id: string }[] = await manager.query(
          `SELECT id FROM devices WHERE id IN (SELECT "deviceId" FROM device_cisco_access WHERE "enableCredentialId"=$1) ORDER BY id FOR UPDATE`,
          [id],
        );
        const changed = await manager.update(
          CiscoEnableCredential,
          { id, ownerId: user.id },
          { name: input.name, sealedSecret: sealCiscoEnable(user.id, id, input.password) },
        );
        if (!changed.affected) throw new NotFoundException("اعتبارنامه پیدا نشد.");
        const freshParents: { id: string }[] = await manager.query(
          `SELECT "deviceId" AS id FROM device_cisco_access WHERE "enableCredentialId"=$1`,
          [id],
        );
        parents.splice(0, parents.length, ...freshParents);
        await this.invalidate(
          manager,
          parents.map((p) => p.id),
        );
        await this.event(
          manager,
          user,
          parents.map((p) => p.id),
          "enable_credential_changed",
        );
      } else
        await manager.insert(CiscoEnableCredential, {
          id: recordId,
          ownerId: user.id,
          name: input.name,
          sealedSecret: sealCiscoEnable(user.id, recordId, input.password),
        });
    });
    return { id: recordId, name: input.name };
  }
  async removeCredential(user: AppUser, id: string) {
    await this.owned(this.db.manager, user, id);
    await this.transaction(async (manager) => {
      const parents: { id: string }[] = await manager.query(
        `SELECT id FROM devices WHERE id IN (SELECT "deviceId" FROM device_cisco_access WHERE "enableCredentialId"=$1) ORDER BY id FOR UPDATE`,
        [id],
      );
      await this.invalidate(
        manager,
        parents.map((p) => p.id),
      );
      await manager.query(
        `UPDATE device_cisco_access SET revision=$2 WHERE "enableCredentialId"=$1`,
        [id, randomUUID()],
      );
      const lockedCredential = await manager.findOne(CiscoEnableCredential, {
        where: { id, ownerId: user.id },
        lock: { mode: "pessimistic_write" },
      });
      if (!lockedCredential) throw new NotFoundException("اعتبارنامه پیدا نشد.");
      const freshParents: { id: string }[] = await manager.query(
        `SELECT "deviceId" AS id FROM device_cisco_access WHERE "enableCredentialId"=$1`,
        [id],
      );
      parents.splice(0, parents.length, ...freshParents);
      await this.invalidate(
        manager,
        parents.map((p) => p.id),
      );
      const result = await manager.delete(CiscoEnableCredential, { id, ownerId: user.id });
      if (!result.affected) throw new NotFoundException("اعتبارنامه پیدا نشد.");
      await this.event(
        manager,
        user,
        parents.map((p) => p.id),
        "enable_credential_deleted",
      );
    });
    return { deleted: true };
  }
  async resolveDraft(
    user: AppUser,
    device: Pick<Device, "type" | "protocol">,
    options?: CiscoRegistrationOptions,
    manager: EntityManager = this.db.manager,
    lock = false,
  ) {
    if (device.type !== "cisco" || device.protocol !== "ssh") {
      if (options) throw new BadRequestException("تنظیم Cisco برای این نوع اتصال معتبر نیست.");
      return undefined;
    }
    const profile = options?.compatibilityProfile ?? "modern";
    const stored = options?.enableCredentialId
      ? await this.owned(manager, user, options.enableCredentialId, lock)
      : null;
    const revision = createHmac("sha256", sshVaultKey())
      .update(JSON.stringify(["cisco-access", profile, stored?.id, stored?.sealedSecret]))
      .digest("hex");
    return {
      config: {
        profile,
        ...(stored
          ? { enableSecret: unsealCiscoEnable(user.id, stored.id, stored.sealedSecret) }
          : {}),
      },
      revision,
    };
  }
  async augment(
    user: AppUser,
    device: Device,
    base: { credentials: SshCredentials; revision: string },
    manager: EntityManager = this.db.manager,
    lock = false,
  ) {
    if (device.type !== "cisco" || device.protocol !== "ssh") return base;
    const settings = await manager.findOne(DeviceCiscoAccess, {
      where: { deviceId: device.id },
      ...(lock ? { lock: { mode: "pessimistic_read" as const } } : {}),
    });
    const resolved = await this.resolveDraft(user, device, settings ?? undefined, manager, lock);
    return {
      credentials: { ...base.credentials, cisco: resolved!.config },
      revision: base.revision + ":" + (settings?.revision ?? "default") + ":" + resolved!.revision,
    };
  }
  async applyRegistration(
    manager: EntityManager,
    user: AppUser,
    device: Device,
    options?: CiscoRegistrationOptions,
  ) {
    if (!options) return;
    this.assertDevice(device);
    await this.resolveDraft(user, device, options, manager, true);
    await manager.insert(DeviceCiscoAccess, {
      deviceId: device.id,
      compatibilityProfile: options.compatibilityProfile,
      enableCredentialId: options.enableCredentialId ?? null,
      revision: randomUUID(),
    });
    await this.event(manager, user, [device.id], "profile_selected");
  }
  async get(user: AppUser, id: string) {
    const device = await this.db
      .getRepository(Device)
      .findOneBy({ id, workspaceOwnerId: this.scope(user) });
    if (!device) throw new NotFoundException("تجهیز پیدا نشد.");
    this.assertDevice(device);
    const settings = await this.db.getRepository(DeviceCiscoAccess).findOneBy({ deviceId: id });
    const owned = settings?.enableCredentialId
      ? await this.db
          .getRepository(CiscoEnableCredential)
          .existsBy({ id: settings.enableCredentialId, ownerId: user.id })
      : false;
    return {
      compatibilityProfile: settings?.compatibilityProfile ?? "modern",
      enableCredentialId: owned ? settings!.enableCredentialId : null,
      enableConfigured: !!settings?.enableCredentialId,
      needsOwnCredential: !!settings?.enableCredentialId && !owned,
      revision: settings?.revision,
      history: await this.db.query(
        `SELECT id,"actorName",action,"compatibilityProfile","enableConfigured","occurredAt" FROM device_cisco_access_events WHERE "deviceId"=$1 AND "companyId" IS NOT DISTINCT FROM $2 AND "occurredAt">now()-interval '30 days' ORDER BY "occurredAt" DESC,id DESC LIMIT 50`,
        [id, device.companyId],
      ),
    };
  }
  async save(user: AppUser, id: string, input: SaveCiscoAccessDto) {
    await this.transaction(async (manager) => {
      const actor = await manager.findOne(AppUser, {
        where: { id: user.id },
        lock: { mode: "pessimistic_read" },
      });
      if (
        !actor?.isActive ||
        actor.role === AppUserRole.COMPANY_EMPLOYEE ||
        this.scope(actor) !== this.scope(user)
      )
        throw new ForbiddenException("ویرایش اتصال Cisco فقط برای مدیر مجاز است.");
      const device = await manager.findOne(Device, {
        where: { id, workspaceOwnerId: this.scope(actor) },
        lock: { mode: "pessimistic_write" },
      });
      if (!device) throw new NotFoundException("تجهیز پیدا نشد.");
      this.assertDevice(device);
      const current = await manager.findOneBy(DeviceCiscoAccess, { deviceId: id });
      if (current ? input.revision !== current.revision : !!input.revision)
        throw new ConflictException("تنظیمات تغییر کرده است. دوباره دریافت کنید.");
      await this.resolveDraft(actor, device, input, manager, true);
      await manager.upsert(
        DeviceCiscoAccess,
        {
          deviceId: id,
          compatibilityProfile: input.compatibilityProfile,
          enableCredentialId: input.enableCredentialId ?? null,
          revision: randomUUID(),
        },
        ["deviceId"],
      );
      await this.invalidate(manager, [id]);
      await this.event(manager, actor, [id], "profile_changed");
    });
    return this.get(user, id);
  }
}
