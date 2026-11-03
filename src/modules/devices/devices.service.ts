import { verifyRecorder } from "./recorder-onvif";
import { randomUUID } from "node:crypto";
import { DeviceCompany, DeviceCredential } from "./device-onboarding.entity";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { IsNull, QueryFailedError, Repository } from "typeorm";
import { AppUser, AppUserRole } from "../users/user.entity";
import { requireSshCredentials, runLinuxSsh, type LinuxSshDto } from "./linux-ssh";
import { DeviceSshProfile } from "./device-ssh-profile.entity";
import { sealSshCredentials, sshVaultKey, unsealSshCredentials } from "./ssh-credential-vault";
import { DeviceCheck } from "./device-check.entity";
import { Device } from "./device.entity";
import { DraftConnectionDto, ListDevicesDto, SaveCredentialDto, SaveDeviceDto } from "./device.dto";
const runPing = promisify(execFile);

const DEVICE_CHECK_LIMIT = 5;

@Injectable()
export class DevicesService {
  private readonly logger = new Logger(DevicesService.name);
  private readonly activeChecks = new Set<string>();

  constructor(@InjectRepository(Device) private readonly devices: Repository<Device>) {}
  private scope(user: AppUser) {
    if (user.allowedSections.length && !user.allowedSections.includes("assets"))
      throw new ForbiddenException("به بخش دارایی‌ها دسترسی ندارید.");
    return user.workspaceOwnerId ?? user.id;
  }
  private writable(user: AppUser) {
    this.scope(user);
    if (user.role === AppUserRole.COMPANY_EMPLOYEE)
      throw new ForbiddenException("ثبت و ویرایش تجهیزات فقط برای ادمین مجاز است.");
  }
  async list(user: AppUser, input: ListDevicesDto) {
    const workspaceOwnerId = this.scope(user);
    const base = this.devices
      .createQueryBuilder("device")
      .where('device."workspaceOwnerId" = :workspaceOwnerId', { workspaceOwnerId });
    const counts = await base
      .clone()
      .select("COUNT(*)", "total")
      .addSelect("COUNT(*) FILTER (WHERE device.status = 'online')", "online")
      .addSelect("COUNT(*) FILTER (WHERE device.status IN ('offline','error'))", "needsReview")
      .addSelect("COUNT(*) FILTER (WHERE device.status = 'unknown')", "unknown")
      .getRawOne<Record<string, string>>();
    if (input.search)
      base.andWhere(
        "(device.name ILIKE :search ESCAPE '\\' OR device.host ILIKE :search ESCAPE '\\' OR device.vendor ILIKE :search ESCAPE '\\' OR array_to_string(device.tags, ' ') ILIKE :search ESCAPE '\\')",
        { search: `%${input.search.replace(/[\\%_]/g, "\\$&")}%` },
      );
    for (const key of ["status", "type", "environment"] as const)
      if (input[key]) base.andWhere(`device.${key} = :${key}`, { [key]: input[key] });
    if (input.category)
      base.andWhere(
        `device.type ${input.category === "recorder" ? "IN" : "NOT IN"} (:...recorders)`,
        { recorders: ["nvr", "dvr"] },
      );
    const [items, total] = await base
      .orderBy(`device.${input.sort}`, input.direction.toUpperCase() as "ASC" | "DESC")
      .addOrderBy("device.id", "ASC")
      .skip((input.page - 1) * input.pageSize)
      .take(input.pageSize)
      .getManyAndCount();
    return {
      items,
      total,
      page: input.page,
      pageSize: input.pageSize,
      stats: {
        total: Number(counts?.total ?? 0),
        online: Number(counts?.online ?? 0),
        needsReview: Number(counts?.needsReview ?? 0),
        unknown: Number(counts?.unknown ?? 0),
      },
    };
  }
  async get(user: AppUser, id: string) {
    const device = await this.devices.findOneBy({ id, workspaceOwnerId: this.scope(user) });
    if (!device) throw new NotFoundException("تجهیز پیدا نشد.");
    return device;
  }
  private async save(device: Device) {
    try {
      return await this.devices.save(device);
    } catch (error) {
      if (
        error instanceof QueryFailedError &&
        (error.driverError as { code?: string }).code === "23505"
      )
        throw new ConflictException(
          "تجهیزی با همین سازنده، آدرس، پورت و پروتکل قبلاً ثبت شده است.",
        );
      throw error;
    }
  }
  async companies(user: AppUser) {
    const workspaceOwnerId = this.scope(user);
    const companies = this.devices.manager.getRepository(DeviceCompany);
    await companies
      .createQueryBuilder()
      .insert()
      .values({
        id: workspaceOwnerId,
        workspaceOwnerId,
        name: "شرکت اصلی",
      })
      .orIgnore()
      .execute();
    return companies.find({ where: { workspaceOwnerId }, order: { name: "ASC" } });
  }

  async createCompany(user: AppUser, name: string) {
    this.writable(user);
    const companies = this.devices.manager.getRepository(DeviceCompany);
    const entry = { id: randomUUID(), workspaceOwnerId: this.scope(user), name };
    const result = await companies
      .createQueryBuilder()
      .insert()
      .values(entry)
      .orIgnore()
      .returning("id")
      .execute();
    if (!result.raw.length) throw new ConflictException("نام شرکت تکراری است.");
    return entry;
  }

  async credentials(user: AppUser) {
    this.scope(user);
    return this.devices.manager.getRepository(DeviceCredential).find({
      where: { ownerId: user.id },
      order: { name: "ASC" },
    });
  }

  private credentialContext(user: AppUser, id: string) {
    return { id, workspaceOwnerId: user.id, host: "credential-library", managementPort: 0 };
  }

  private async getCredential(user: AppUser, id: string) {
    const entry = await this.devices.manager
      .getRepository(DeviceCredential)
      .createQueryBuilder("credential")
      .addSelect("credential.sealedCredentials")
      .where("credential.id = :id AND credential.ownerId = :ownerId", { id, ownerId: user.id })
      .getOne();
    if (!entry) throw new NotFoundException("اعتبارنامه پیدا نشد.");
    return entry;
  }

  async saveCredential(user: AppUser, input: SaveCredentialDto, id?: string) {
    this.scope(user);
    const { name } = input;
    const secret = requireSshCredentials(input);
    const { username } = secret;
    const credentials = this.devices.manager.getRepository(DeviceCredential);
    const credentialId = id ?? randomUUID();
    const data = {
      name,
      username,
      sealedCredentials: sealSshCredentials(
        this.credentialContext(user, credentialId),
        secret,
        sshVaultKey(),
      ),
    };
    if (id) {
      const result = await credentials.update({ id, ownerId: user.id }, data);
      if (!result.affected) throw new NotFoundException("اعتبارنامه پیدا نشد.");
    } else {
      await credentials.insert({ id: credentialId, ownerId: user.id, ...data });
    }
    return { id: credentialId, name, username };
  }

  async deleteCredential(user: AppUser, id: string) {
    this.scope(user);
    const result = await this.devices.manager
      .getRepository(DeviceCredential)
      .delete({ id, ownerId: user.id });
    if (!result.affected) throw new NotFoundException("اعتبارنامه پیدا نشد.");
    return { deleted: true };
  }

  private async checkCompany(user: AppUser, companyId?: string) {
    const companies = await this.companies(user);
    const company = companyId ? companies.find((item) => item.id === companyId) : companies[0];
    if (!company) throw new NotFoundException("شرکت در فضای کاری شما پیدا نشد.");
    return company.id;
  }

  async create(user: AppUser, input: SaveDeviceDto) {
    if (!input.companyId) this.writable(user);
    const companyId = await this.checkCompany(user, input.companyId);
    if (input.credentialId) {
      if (input.type !== "linux_edge" || input.protocol !== "ssh")
        throw new BadRequestException("این اعتبارنامه برای اتصال Linux با SSH است.");
      await this.getCredential(user, input.credentialId);
    }
    return this.save(
      this.devices.create({
        ...input,
        companyId,
        workspaceOwnerId: this.scope(user),
        status: "unknown",
        lastSeenAt: null,
      }),
    );
  }
  async update(user: AppUser, id: string, input: SaveDeviceDto) {
    this.writable(user);
    const device = await this.get(user, id);
    const connectionChanged =
      device.host !== input.host ||
      device.managementPort !== input.managementPort ||
      device.protocol !== input.protocol ||
      device.type !== input.type ||
      device.vendor !== input.vendor;
    if (input.companyId === null) throw new BadRequestException("شرکت مالک تجهیز الزامی است.");
    if (input.companyId) await this.checkCompany(user, input.companyId);
    if (input.credentialId) {
      if (input.type !== "linux_edge" || input.protocol !== "ssh")
        throw new BadRequestException("این اعتبارنامه برای اتصال Linux با SSH است.");
      await this.getCredential(user, input.credentialId);
    }
    Object.assign(device, input);
    if (connectionChanged) {
      device.status = "unknown";
      device.lastSeenAt = null;
    }
    return this.save(device);
  }
  async history(user: AppUser, id: string) {
    const device = await this.get(user, id);
    return this.devices.manager.getRepository(DeviceCheck).find({
      where: { deviceId: device.id },
      order: { checkedAt: "DESC", id: "DESC" },
      take: DEVICE_CHECK_LIMIT,
    });
  }

  async testConnection(user: AppUser, id: string) {
    this.writable(user);
    const device = await this.get(user, id);
    if (this.activeChecks.has(id)) throw new ConflictException("تست این تجهیز در حال اجراست.");
    if (this.activeChecks.size >= 8)
      throw new ServiceUnavailableException("ظرفیت تست اتصال پر است. کمی بعد تلاش کنید.");

    this.activeChecks.add(id);
    try {
      let output: string;
      try {
        const result = await runPing(
          "ping",
          ["-n", "-c", "3", "-W", "2", "-w", "6", "--", device.host],
          {
            timeout: 9000,
            maxBuffer: 16384,
            env: { ...process.env, LC_ALL: "C" },
          },
        );
        output = result.stdout;
      } catch (error) {
        const failure = error as {
          code?: number | string;
          signal?: string;
          stdout?: string;
          stderr?: string;
        };
        const noRoute =
          failure.code === 2 &&
          /(?:Network is unreachable|No route to host)/.test(failure.stderr ?? "");
        if (failure.code !== 1 && !noRoute) {
          this.logger.warn(
            `Ping failed for device ${id} (code: ${failure.code ?? "none"}, signal: ${failure.signal ?? "none"})`,
          );
          throw new ServiceUnavailableException(
            "اجرای پینگ از سمت سرور ممکن نشد. آدرس و دسترسی ICMP سرور را بررسی کنید.",
          );
        }
        output = failure.stdout ?? "";
      }

      // With a deadline, iputils can exit with code 1 even after receiving a reply.
      const replies = output.match(/, (\d+) (?:packets? )?received\b/);
      const reachable = Number(replies?.[1] ?? 0) > 0;
      const average = output.match(/= [\d.]+\/([\d.]+)\/[\d.]+\/[\d.]+ ms/);
      const latencyMs = reachable && average ? Number(average[1]) : null;

      const checkedAt = new Date();
      const status = reachable ? "online" : "offline";
      await this.devices.manager.transaction(async (manager) => {
        const result = await manager.getRepository(Device).update(
          {
            id,
            workspaceOwnerId: device.workspaceOwnerId,
            deletedAt: IsNull(),
            host: device.host,
            managementPort: device.managementPort,
            protocol: device.protocol,
            type: device.type,
            vendor: device.vendor,
          },
          { status, ...(reachable ? { lastSeenAt: checkedAt } : {}) },
        );
        if (!result.affected)
          throw new ConflictException("مشخصات تجهیز در حین تست تغییر کرد. دوباره تست کنید.");
        await manager.insert(DeviceCheck, {
          deviceId: id,
          host: device.host,
          status,
          latencyMs,
          checkedAt,
        });
        await manager.query(
          `DELETE FROM "device_checks" WHERE "id" IN (
            SELECT "id" FROM "device_checks"
            WHERE "deviceId" = $1
            ORDER BY "checkedAt" DESC, "id" DESC
            OFFSET $2
          )`,
          [id, DEVICE_CHECK_LIMIT],
        );
      });
      return {
        reachable,
        status,
        latencyMs,
        checkedAt,
        lastSeenAt: reachable ? checkedAt : device.lastSeenAt,
      };
    } finally {
      this.activeChecks.delete(id);
    }
  }
  async testDraftConnection(user: AppUser, input: DraftConnectionDto) {
    if (!input.device.companyId) this.writable(user);
    await this.checkCompany(user, input.device.companyId);
    const recorder = ["nvr", "dvr"].includes(input.device.type);
    if (recorder && (!input.recorder || input.device.protocol !== "api"))
      throw new BadRequestException(
        "نام کاربری و گذرواژه ضبط‌کننده را برای اتصال ONVIF وارد کنید.",
      );
    if (!recorder && (input.device.type !== "linux_edge" || input.device.protocol !== "ssh"))
      throw new BadRequestException(
        "تست اعتبارنامه برای SSH در Linux و ONVIF در ضبط‌کننده فعال است.",
      );
    const stored = input.device.credentialId
      ? await this.getCredential(user, input.device.credentialId)
      : undefined;
    const credentials = stored
      ? unsealSshCredentials(
          this.credentialContext(user, stored.id),
          stored.sealedCredentials,
          sshVaultKey(),
        )
      : input.credentials;
    const check = `draft:${user.id}`;
    if (this.activeChecks.has(check) || this.activeChecks.size >= 8)
      throw new ConflictException("تست دیگری در حال اجراست. کمی بعد تلاش کنید.");
    this.activeChecks.add(check);
    try {
      if (recorder && input.recorder) {
        await verifyRecorder(input.device.host, input.device.managementPort, input.recorder);
        return { verified: true, checkedAt: new Date().toISOString() };
      }
      const secret = requireSshCredentials(credentials ?? {});
      const { checkedAt } = await runLinuxSsh(this.devices.create(input.device), {
        operation: "verify",
        ...secret,
      });
      return { verified: true, checkedAt };
    } finally {
      this.activeChecks.delete(check);
    }
  }

  async linuxSsh(user: AppUser, id: string, input: LinuxSshDto) {
    this.writable(user);
    const device = await this.get(user, id);
    if (device.type !== "linux_edge" || device.protocol !== "ssh")
      throw new BadRequestException("این عملیات برای تجهیز Linux با پروتکل SSH در دسترس است.");
    if (this.activeChecks.has(id) || this.activeChecks.size >= 8)
      throw new ConflictException("تست یا عملیات دیگری در حال اجراست. کمی بعد تلاش کنید.");

    this.activeChecks.add(id);
    try {
      const profiles = this.devices.manager.getRepository(DeviceSshProfile);
      if (input.useSaved) {
        if (
          input.saveConnection ||
          input.username ||
          input.hostKey ||
          input.privateKey ||
          input.password
        )
          throw new BadRequestException("حالت استفاده از اتصال ذخیره‌شده را جداگانه انتخاب کنید.");
        const profile = await profiles.findOneBy({ deviceId: id });
        if (!profile && device.credentialId) {
          const stored = await this.getCredential(user, device.credentialId);
          const credentials = unsealSshCredentials(
            this.credentialContext(user, stored.id),
            stored.sealedCredentials,
            sshVaultKey(),
          );
          return await runLinuxSsh(device, { ...credentials, operation: input.operation });
        }
        if (!profile) throw new NotFoundException("اتصال SSH برای تجهیز ثبت نشده است.");
        const credentials = unsealSshCredentials(device, profile.sealedCredentials, sshVaultKey());
        return await runLinuxSsh(device, { ...credentials, operation: input.operation });
      }

      const credentials = requireSshCredentials(input);
      if (input.saveConnection && input.operation !== "verify")
        throw new BadRequestException("برای ذخیره اتصال، عملیات تأیید ورود را انتخاب کنید.");
      const key = input.saveConnection ? sshVaultKey() : undefined;
      const result = await runLinuxSsh(device, { ...credentials, operation: input.operation });
      if (!key) return result;

      await this.devices.manager.transaction(async (manager) => {
        const current = await manager.findOne(Device, {
          where: {
            id,
            workspaceOwnerId: device.workspaceOwnerId,
            host: device.host,
            managementPort: device.managementPort,
            type: "linux_edge",
            protocol: "ssh",
          },
          lock: { mode: "pessimistic_write" },
        });
        if (!current)
          throw new ConflictException("مشخصات تجهیز تغییر کرد. اتصال را دوباره تست کنید.");
        await manager.upsert(
          DeviceSshProfile,
          {
            deviceId: id,
            sealedCredentials: sealSshCredentials(current, credentials, key),
          },
          ["deviceId"],
        );
      });
      return { ...result, saved: true };
    } finally {
      this.activeChecks.delete(id);
    }
  }

  async archive(user: AppUser, id: string) {
    this.writable(user);
    const device = await this.get(user, id);
    await this.devices.softRemove(device);
    return { message: "تجهیز از فهرست فعال بایگانی شد." };
  }
}
