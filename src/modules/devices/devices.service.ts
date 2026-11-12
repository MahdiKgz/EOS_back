import { CiscoAccessService } from "./cisco-access.service";
import { DeviceCiscoAccess } from "./cisco-access.entity";
import { collectEsxiSshInventory } from "./esxi-ssh-collector";
import { collectVendorApi, type ApiInventory } from "./vendor-api-collector";
import { vendorApiKind, type VendorApiKind } from "./vendor-api-kind";
import { VendorApiError } from "./vendor-https";
import { DeviceApiCredential } from "./vendor-api-credential.entity";
import { VendorApiCredentialsService } from "./vendor-api-credentials.service";
import { EsxiSoapError } from "./esxi-soap";
import { DeviceSecondaryChannel } from "./device-channels.entity";
import { inspectOnvif, snapshotOnvif, verifyOnvifStream } from "./recorder-onvif";
import { inspectDvrip } from "./recorder-dvrip";
import { discoverRecorders } from "./recorder-discovery";
import { inspectAppWeb, verifyRecorderConnection } from "./recorder-connection";
import { createHash, createHmac, randomUUID } from "node:crypto";
import { DeviceCompany, DeviceCredential } from "./device-onboarding.entity";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  BadGatewayException,
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { InjectRepository } from "@nestjs/typeorm";
import { IsNull, Not, QueryFailedError, Repository } from "typeorm";
import { AppUser, AppUserRole } from "../users/user.entity";
import { requireSshCredentials, runLinuxSsh, type LinuxSshDto } from "./linux-ssh";
import { DeviceSshProfile } from "./device-ssh-profile.entity";
import {
  recorderVaultKey,
  sealRecorderCredentials,
  unsealRecorderCredentials,
  sealSshCredentials,
  sshVaultKey,
  unsealSshCredentials,
} from "./ssh-credential-vault";
import { DeviceCheck } from "./device-check.entity";
import { Device } from "./device.entity";
import {
  CreateDeviceDto,
  DiscoverRecordersDto,
  DraftConnectionDto,
  ListDevicesDto,
  AssetsOverviewQueryDto,
  RegistrationDraftDto,
  VerifyRecorderDto,
  SaveCredentialDto,
  SaveDeviceDto,
} from "./device.dto";
const runPing = promisify(execFile);

const DEVICE_CHECK_LIMIT = 5;

@Injectable()
export class DevicesService {
  private readonly logger = new Logger(DevicesService.name);
  private readonly activeChecks = new Set<string>();

  private readonly verificationJwt: JwtService;

  constructor(
    @InjectRepository(Device) private readonly devices: Repository<Device>,
    config: ConfigService,
    private readonly apiCredentials: VendorApiCredentialsService,
    private readonly ciscoAccess: CiscoAccessService,
  ) {
    this.verificationJwt = new JwtService({
      secret: createHmac("sha256", config.getOrThrow<string>("JWT_SECRET"))
        .update("device-onboarding-verification")
        .digest(),
      signOptions: { algorithm: "HS256", expiresIn: 600 },
      verifyOptions: { algorithms: ["HS256"] },
    });
  }

  private verificationBinding(
    user: AppUser,
    device: SaveDeviceDto | Device,
    companyId: string,
    stored?: Pick<DeviceCredential, "id" | "sealedCredentials">,
    ciscoBinding?: string,
  ) {
    return createHash("sha256")
      .update(
        JSON.stringify([
          user.id,
          this.scope(user),
          companyId,
          device.type,
          device.vendor,
          device.host,
          device.managementPort,
          device.protocol,
          device.accessRoute ?? "direct",
          device.apiCredentialId,
          stored?.id,
          stored?.sealedCredentials,
          ...(ciscoBinding ? [ciscoBinding] : []),
        ]),
      )
      .digest("hex");
  }
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
  async assetsOverview(user: AppUser, input: AssetsOverviewQueryDto) {
    const workspace = this.scope(user);
    const search = input.search ? `%${input.search.replace(/[\\%_]/g, "\\$&")}%` : null;
    const [result] = await this.devices.manager.query(
      `WITH inventory AS (
      SELECT device."id",device."name",device."vendor",device."type",device."host",device."location",device."managementPort",device."protocol",device."status",device."lastSeenAt",device."createdAt",device."companyId",
        company."name" AS "companyName", (device."verification" IS NOT NULL) AS verified
      FROM "devices" device LEFT JOIN "device_companies" company ON company."id"=device."companyId" AND company."workspaceOwnerId"=$1
      WHERE device."workspaceOwnerId"=$1 AND device."deletedAt" IS NULL AND ($2::text IS NULL OR device."companyId"=$2)
    ), type_counts AS (SELECT "type" AS key,COUNT(*)::integer AS count FROM inventory GROUP BY "type"),
    vendor_counts AS (SELECT "vendor" AS key,COUNT(*)::integer AS count FROM inventory GROUP BY "vendor"), filtered AS (
      SELECT * FROM inventory WHERE
      ($3::text IS NULL OR "name" ILIKE $3 ESCAPE '\\' OR "host" ILIKE $3 ESCAPE '\\' OR "vendor" ILIKE $3 ESCAPE '\\' OR "location" ILIKE $3 ESCAPE '\\')
      AND ($4='all' OR ($4='online' AND "status"='online') OR ($4='attention' AND "status"<>'online') OR ($4='unverified' AND NOT verified))
    ) SELECT (SELECT COUNT(*) FROM filtered)::integer AS total,
      json_build_object('total',(SELECT COUNT(*) FROM inventory),'online',(SELECT COUNT(*) FROM inventory WHERE status='online'),
        'attention',(SELECT COUNT(*) FROM inventory WHERE status<>'online'),'unverified',(SELECT COUNT(*) FROM inventory WHERE NOT verified)) AS stats,
      json_build_object(
        'status',json_build_object('online',(SELECT COUNT(*) FROM inventory WHERE status='online'),'offline',(SELECT COUNT(*) FROM inventory WHERE status='offline'),
          'error',(SELECT COUNT(*) FROM inventory WHERE status='error'),'unknown',(SELECT COUNT(*) FROM inventory WHERE status='unknown')),
        'types',COALESCE((SELECT json_agg(type_counts ORDER BY count DESC,key) FROM type_counts),'[]'),
        'vendors',COALESCE((SELECT json_agg(top_vendors ORDER BY count DESC,key) FROM (SELECT * FROM vendor_counts ORDER BY count DESC,key LIMIT 5) top_vendors),'[]')
      ) AS analytics,
      COALESCE((SELECT json_agg(row ORDER BY row."createdAt" DESC,row."id" DESC) FROM (SELECT * FROM filtered ORDER BY "createdAt" DESC,"id" DESC LIMIT $5 OFFSET $6) row),'[]') AS items`,
      [
        workspace,
        input.companyId ?? null,
        search,
        input.filter,
        input.pageSize,
        (input.page - 1) * input.pageSize,
      ],
    );
    return { ...result, page: input.page, pageSize: input.pageSize };
  }
  async list(user: AppUser, input: ListDevicesDto) {
    const workspaceOwnerId = this.scope(user);
    const base = this.devices
      .createQueryBuilder("device")
      .where('device."workspaceOwnerId" = :workspaceOwnerId', { workspaceOwnerId });
    if (input.inventory === "archived") base.withDeleted().andWhere("device.deletedAt IS NOT NULL");
    if (input.companyId)
      base.andWhere('device."companyId" = :companyId', { companyId: input.companyId });
    if (input.category)
      base.andWhere(
        `device.type ${input.category === "recorder" ? "IN" : "NOT IN"} (:...recorders)`,
        { recorders: ["nvr", "dvr", "camera"] },
      );
    const counts = await base
      .clone()
      .select("COUNT(*)", "total")
      .addSelect("COUNT(*) FILTER (WHERE device.status = 'online')", "online")
      .addSelect("COUNT(*) FILTER (WHERE device.status IN ('offline','error'))", "needsReview")
      .addSelect("COUNT(*) FILTER (WHERE device.status = 'unknown')", "unknown")
      .getRawOne<Record<string, string>>();
    if (input.search)
      base.andWhere(
        "(device.name ILIKE :search ESCAPE '\\' OR device.host ILIKE :search ESCAPE '\\' OR device.vendor ILIKE :search ESCAPE '\\' OR device.location ILIKE :search OR array_to_string(device.tags, ' ') ILIKE :search ESCAPE '\\')",
        { search: `%${input.search.replace(/[\\%_]/g, "\\$&")}%` },
      );
    for (const key of ["status", "type", "environment"] as const)
      if (input[key]) base.andWhere(`device.${key} = :${key}`, { [key]: input[key] });
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
  private async save(device: Device, repository = this.devices) {
    try {
      return await repository.save(device);
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
      await this.getCredential(user, id);
      await this.devices.manager.transaction(async (manager) => {
        await this.lockSshCredentialParents(manager, id);
        const result = await manager
          .getRepository(DeviceCredential)
          .update({ id, ownerId: user.id }, data);
        if (!result.affected) throw new NotFoundException("اعتبارنامه پیدا نشد.");
        await this.invalidateSshCredentialParents(manager, id);
      });
    } else await credentials.insert({ id: credentialId, ownerId: user.id, ...data });

    return { id: credentialId, name, username };
  }

  private lockSshCredentialParents(manager: Repository<Device>["manager"], id: string) {
    return manager.query(
      `SELECT "id" FROM "devices" WHERE "credentialId"=$1 OR "id" IN (SELECT "deviceId" FROM "device_secondary_channels" WHERE "credentialId"=$1) ORDER BY "id" FOR UPDATE`,
      [id],
    );
  }
  private async invalidateSshCredentialParents(manager: Repository<Device>["manager"], id: string) {
    await manager.query(
      `UPDATE device_capability_cache SET "binding"=NULL,"expiresAt"=NULL,"leaseToken"=NULL,"leaseExpiresAt"=NULL WHERE "deviceId" IN (SELECT "id" FROM devices WHERE "credentialId"=$1 UNION SELECT "deviceId" FROM device_secondary_channels WHERE "credentialId"=$1)`,
      [id],
    );
    await manager.query(`UPDATE "devices" SET "verification"=NULL WHERE "credentialId"=$1`, [id]);
    await manager.query(
      `UPDATE "device_monitoring" SET "enabled"=false,"nextRunAt"=NULL,"leaseToken"=NULL,"leaseExpiresAt"=NULL,"lastErrorCode"='MONITOR_CONFIGURATION_INVALID',"revision"=$2 WHERE "deviceId" IN (SELECT "id" FROM "devices" WHERE "credentialId"=$1 UNION SELECT "deviceId" FROM "device_secondary_channels" WHERE "credentialId"=$1)`,
      [id, randomUUID()],
    );
  }
  async deleteCredential(user: AppUser, id: string) {
    this.scope(user);
    await this.getCredential(user, id);
    await this.devices.manager.transaction(async (manager) => {
      await this.lockSshCredentialParents(manager, id);
      // Check ownership before changing any dependent device state.
      const credential = await manager.findOne(DeviceCredential, {
        where: { id, ownerId: user.id },
        lock: { mode: "pessimistic_write" },
      });
      if (!credential) throw new NotFoundException("اعتبارنامه پیدا نشد.");
      await this.invalidateSshCredentialParents(manager, id);
      await manager.delete(DeviceCredential, { id, ownerId: user.id });
    });
    return { deleted: true };
  }

  private async checkCompany(user: AppUser, companyId?: string) {
    const companies = await this.companies(user);
    const company = companyId ? companies.find((item) => item.id === companyId) : companies[0];
    if (!company) throw new NotFoundException("شرکت در فضای کاری شما پیدا نشد.");
    return company.id;
  }

  async create(
    user: AppUser,
    { verificationToken, draftRevision, ciscoProfile, ...input }: CreateDeviceDto,
  ) {
    if (!input.companyId) this.writable(user);
    const companyId = await this.checkCompany(user, input.companyId);
    const cisco = await this.ciscoAccess.resolveDraft(user, input, ciscoProfile);
    let stored: Pick<DeviceCredential, "id" | "sealedCredentials"> | undefined;
    if (input.apiCredentialId) {
      this.assertVendorApi(input);
      if (input.credentialId)
        throw new BadRequestException("اعتبارنامهٔ SSH و API را جداگانه انتخاب کنید.");
      stored = await this.apiCredentials.get(user, input.apiCredentialId);
    }
    if (input.credentialId) {
      if (
        !["linux_edge", "mikrotik", "pfsense", "esxi", "fortigate", "cisco"].includes(input.type) ||
        input.protocol !== "ssh"
      )
        throw new BadRequestException(
          "این اعتبارنامه برای اتصال SSH به Linux، MikroTik، pfSense، ESXi FortiGate یا Cisco است.",
        );
      stored = await this.getCredential(user, input.credentialId);
    }
    const device = this.devices.create({
      ...input,
      location: input.location || null,
      companyId,
      workspaceOwnerId: this.scope(user),
      verification: null,
      status: "unknown",
      lastSeenAt: null,
    });
    if (verificationToken) {
      try {
        const proof = this.verificationJwt.verify<{
          binding: string;
          checkedAt: string;
          identity?: Record<string, string>;
          sealedRecorder?: string;
        }>(verificationToken);
        if (
          proof.binding !==
          this.verificationBinding(user, input, companyId, stored, cisco?.revision)
        )
          throw new Error("Verification target changed");
        device.verification = { checkedAt: proof.checkedAt, identity: proof.identity };
        if (proof.sealedRecorder) {
          const key = recorderVaultKey();
          const draftContext = { ...device, id: proof.binding };
          const credentials = unsealRecorderCredentials(draftContext, proof.sealedRecorder, key);
          device.sealedRecorderCredentials = sealRecorderCredentials(device, credentials, key);
        }
      } catch {
        throw new BadRequestException("نتیجهٔ تأیید معتبر نیست. تست اتصال را دوباره انجام دهید.");
      }
    }
    const saved = await this.devices.manager.transaction(async (manager) => {
      const actor = await manager.findOne(AppUser, {
        where: { id: user.id },
        lock: { mode: "pessimistic_read" },
      });
      if (!actor?.isActive || this.scope(actor) !== this.scope(user))
        throw new ForbiddenException("دسترسی ثبت تجهیز تغییر کرده است.");
      if (!input.companyId) this.writable(actor);
      const freshCisco = await this.ciscoAccess.resolveDraft(
        actor,
        input,
        ciscoProfile,
        manager,
        true,
      );
      if (freshCisco?.revision !== cisco?.revision)
        throw new ConflictException(
          "تنظیم Cisco یا رمز enable تغییر کرده است. تست اتصال را دوباره انجام دهید.",
        );
      if (input.credentialId) {
        const current = await manager.findOne(DeviceCredential, {
          where: { id: input.credentialId, ownerId: actor.id },
          select: { id: true, sealedCredentials: true },
          lock: { mode: "pessimistic_read" },
        });
        if (!current || current.sealedCredentials !== stored?.sealedCredentials)
          throw new ConflictException("اعتبارنامه تغییر کرده است. دوباره تست کنید.");
      }
      if (input.apiCredentialId) {
        const current = await manager.getRepository(DeviceApiCredential).findOne({
          where: { id: input.apiCredentialId, ownerId: user.id },
          select: { id: true, sealedCredentials: true },
          lock: { mode: "pessimistic_read" },
        });
        if (!current || current.sealedCredentials !== stored?.sealedCredentials)
          throw new ConflictException("اعتبارنامه تغییر کرده است. تست اتصال را دوباره انجام دهید.");
      }
      const registered = await this.save(device, manager.getRepository(Device));
      await this.ciscoAccess.applyRegistration(manager, actor, registered, ciscoProfile);
      if (draftRevision) await this.deleteRegistrationDraft(user, draftRevision, manager);
      return registered;
    });
    delete saved.sealedRecorderCredentials;
    return saved;
  }
  async update(user: AppUser, id: string, input: SaveDeviceDto) {
    this.writable(user);
    const workspaceOwnerId = this.scope(user);
    if (input.companyId === null) throw new BadRequestException("شرکت مالک تجهیز الزامی است.");
    if (input.companyId) await this.checkCompany(user, input.companyId);
    if (input.credentialId) {
      if (
        !["linux_edge", "mikrotik", "pfsense", "esxi", "fortigate", "cisco"].includes(input.type) ||
        input.protocol !== "ssh"
      )
        throw new BadRequestException(
          "این اعتبارنامه برای اتصال SSH به Linux، MikroTik، pfSense، ESXi، FortiGate یا Cisco است.",
        );
      await this.getCredential(user, input.credentialId);
    }
    if (input.apiCredentialId) {
      this.assertVendorApi(input);
      if (input.credentialId)
        throw new BadRequestException("اعتبارنامهٔ SSH و API را جداگانه انتخاب کنید.");
      await this.apiCredentials.get(user, input.apiCredentialId);
    }
    return this.devices.manager.transaction(async (manager) => {
      const repository = manager.getRepository(Device);
      const device = await repository.findOne({
        where: { id, workspaceOwnerId },
        lock: { mode: "pessimistic_write" },
      });
      if (!device) throw new NotFoundException("تجهیز پیدا نشد.");
      if (input.apiCredentialId)
        await this.apiCredentials.get(user, input.apiCredentialId, manager, true);
      const companyChanged = input.companyId !== undefined && input.companyId !== device.companyId;
      const credentialChanged =
        (input.credentialId !== undefined && input.credentialId !== device.credentialId) ||
        (input.apiCredentialId !== undefined && input.apiCredentialId !== device.apiCredentialId);
      const connectionChanged =
        device.host !== input.host ||
        device.managementPort !== input.managementPort ||
        device.protocol !== input.protocol ||
        device.type !== input.type ||
        device.vendor !== input.vendor;
      if (
        connectionChanged ||
        companyChanged ||
        (input.credentialId !== undefined && input.credentialId !== device.credentialId) ||
        (input.apiCredentialId !== undefined && input.apiCredentialId !== device.apiCredentialId)
      )
        device.verification = null;
      const { location, companyId, credentialId, apiCredentialId, accessRoute, ...fields } = input;
      Object.assign(device, fields);
      if (location !== undefined) device.location = location || null;
      if (companyId !== undefined) device.companyId = companyId;
      if (credentialId !== undefined) device.credentialId = credentialId;
      if (apiCredentialId !== undefined) device.apiCredentialId = apiCredentialId;
      if (!vendorApiKind(device)) device.apiCredentialId = null;
      if (accessRoute !== undefined) device.accessRoute = accessRoute;
      if (companyChanged) {
        device.credentialId = null;
        device.apiCredentialId = null;
        await manager.update(
          DeviceSecondaryChannel,
          { deviceId: id },
          {
            credentialId: null,
            snmpCredentialId: null,
            apiCredentialId: null,
            enabled: false,
            status: "configured",
            verifiedBinding: null,
            testToken: null,
            testExpiresAt: null,
            revision: randomUUID(),
            telemetry: null,
          },
        );
        await manager.delete(DeviceSshProfile, { deviceId: id });
      }
      if (connectionChanged || companyChanged || credentialChanged) {
        await manager.query(
          `UPDATE device_capability_cache SET "binding"=NULL,"expiresAt"=NULL,"leaseToken"=NULL,"leaseExpiresAt"=NULL WHERE "deviceId"=$1`,
          [id],
        );
        await manager.query(
          `UPDATE "device_monitoring" SET "enabled"=false,"nextRunAt"=NULL,"latest"=NULL,"generation"=NULL,"counterEpoch"=NULL,"leaseToken"=NULL,"leaseExpiresAt"=NULL,"revision"=$2 WHERE "deviceId"=$1`,
          [id, randomUUID()],
        );
      }
      if (connectionChanged || companyChanged)
        await manager.delete(DeviceCiscoAccess, { deviceId: id });
      if (connectionChanged || companyChanged) {
        device.sealedRecorderCredentials = null;
        device.status = "unknown";
        device.lastSeenAt = null;
      }
      const saved = await this.save(device, repository);
      if (companyChanged) await this.recordInventoryEvent(manager, user, id, "transferred");
      delete saved.sealedRecorderCredentials;
      return saved;
    });
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
  private recorderCredentials(type: string, input: import("./device.dto").RecorderConnectionDto) {
    if (type !== "camera") return input;
    if (input.mode && !["onvif", "rtsp"].includes(input.mode))
      throw new BadRequestException("برای دوربین مستقل، روش ONVIF یا RTSP را انتخاب کنید.");
    return { ...input, mode: input.mode ?? ("onvif" as const) };
  }
  async testDraftConnection(user: AppUser, input: DraftConnectionDto) {
    if (!input.device.companyId) this.writable(user);
    const companyId = await this.checkCompany(user, input.device.companyId);
    const vendorApi = !!vendorApiKind(input.device);
    const recorder = ["nvr", "dvr", "camera"].includes(input.device.type);
    if (recorder && (!input.recorder || input.device.protocol !== "api"))
      throw new BadRequestException(
        "نام کاربری و گذرواژه ضبط‌کننده را برای اتصال ONVIF وارد کنید.",
      );
    if (
      !recorder &&
      !vendorApi &&
      (!["linux_edge", "mikrotik", "pfsense", "esxi", "fortigate", "cisco"].includes(
        input.device.type,
      ) ||
        input.device.protocol !== "ssh")
    )
      throw new BadRequestException(
        "تست اعتبارنامه برای SSH در Linux، MikroTik، pfSense، ESXi، FortiGate و Cisco و ONVIF در ضبط‌کننده فعال است.",
      );
    if (input.device.apiCredentialId && !vendorApi)
      throw new BadRequestException("اعتبارنامهٔ API برای این روش اتصال معتبر نیست.");
    if (input.device.apiCredentialId && input.device.credentialId)
      throw new BadRequestException("اعتبارنامهٔ SSH و API را جداگانه انتخاب کنید.");
    if (vendorApi && !input.device.apiCredentialId)
      throw new BadRequestException("اعتبارنامهٔ API را انتخاب کنید.");
    const stored = vendorApi
      ? await this.apiCredentials.get(user, input.device.apiCredentialId!)
      : input.device.credentialId
        ? await this.getCredential(user, input.device.credentialId)
        : undefined;
    const credentials =
      stored && !vendorApi
        ? unsealSshCredentials(
            this.credentialContext(user, stored.id),
            stored.sealedCredentials,
            sshVaultKey(),
          )
        : input.credentials;
    const cisco = await this.ciscoAccess.resolveDraft(
      user,
      input.device,
      input.device.ciscoProfile,
    );
    const binding = this.verificationBinding(
      user,
      input.device,
      companyId,
      stored,
      cisco?.revision,
    );
    const verified = (
      checkedAt: string,
      identity?: Record<string, string>,
      sealedRecorder?: string,
    ) => ({
      verified: true,
      checkedAt,
      identity,
      verificationToken: this.verificationJwt.sign({
        checkedAt,
        identity,
        binding,
        sealedRecorder,
      }),
    });
    const check = `draft:${user.id}`;
    if (this.activeChecks.has(check) || this.activeChecks.size >= 8)
      throw new ConflictException("تست دیگری در حال اجراست. کمی بعد تلاش کنید.");
    this.activeChecks.add(check);
    try {
      if (vendorApi && stored) {
        const target = this.devices.create({
          ...input.device,
          companyId,
          workspaceOwnerId: this.scope(user),
        });
        const inventory = await this.collectApi(target, this.apiCredentials.secret(user, stored));
        return verified(inventory.collectedAt, this.apiIdentity(inventory));
      }
      if (recorder && input.recorder) {
        const recorderInput = this.recorderCredentials(input.device.type, input.recorder);
        const { identity, mode } = await verifyRecorderConnection(
          input.device.host,
          input.device.managementPort,
          recorderInput,
        );
        const sealedRecorder = input.saveRecorderConnection
          ? sealRecorderCredentials(
              {
                id: binding,
                workspaceOwnerId: this.scope(user),
                host: input.device.host,
                managementPort: input.device.managementPort,
              },
              { ...recorderInput, mode },
              recorderVaultKey(),
            )
          : undefined;
        return verified(new Date().toISOString(), identity, sealedRecorder);
      }
      const secret = {
        ...requireSshCredentials(credentials ?? {}),
        ...(cisco ? { cisco: cisco.config } : {}),
      };
      const { checkedAt, identity } = await runLinuxSsh(this.devices.create(input.device), {
        operation: "verify",
        ...secret,
      });
      return verified(checkedAt, identity);
    } finally {
      this.activeChecks.delete(check);
    }
  }

  async registrationDraft(user: AppUser) {
    const [record] = await this.devices.manager.query(
      `SELECT "revision", "expiresAt", "draft" FROM "device_registration_drafts"
       WHERE "userId" = $1 AND "workspaceOwnerId" = $2 AND "expiresAt" > now()`,
      [user.id, this.scope(user)],
    );
    return record
      ? { ...record.draft, revision: record.revision, expiresAt: record.expiresAt.getTime() }
      : null;
  }

  async saveRegistrationDraft(user: AppUser, input: RegistrationDraftDto) {
    const scope = this.scope(user);
    if (input.companyId) await this.checkCompany(user, input.companyId);
    const revision = randomUUID();
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
    await this.devices.manager.query(
      `INSERT INTO "device_registration_drafts" ("userId", "workspaceOwnerId", "revision", "expiresAt", "draft")
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT ("userId") DO UPDATE SET
         "workspaceOwnerId" = EXCLUDED."workspaceOwnerId", "revision" = EXCLUDED."revision",
         "expiresAt" = EXCLUDED."expiresAt", "draft" = EXCLUDED."draft"`,
      [user.id, scope, revision, new Date(expiresAt), JSON.stringify(input)],
    );
    return { revision, expiresAt };
  }

  async deleteRegistrationDraft(user: AppUser, revision: string, manager = this.devices.manager) {
    await manager.query(
      `DELETE FROM "device_registration_drafts"
       WHERE "userId" = $1 AND "workspaceOwnerId" = $2 AND "revision"::text = $3`,
      [user.id, this.scope(user), revision],
    );
    return { deleted: true };
  }

  async discoverRecorders(user: AppUser, input: DiscoverRecordersDto) {
    await this.checkCompany(user, input.companyId);
    const lock = `recorder-discovery:${this.scope(user)}`;
    if (this.activeChecks.has(lock) || this.activeChecks.size >= 8)
      throw new ConflictException("جست‌وجوی دیگری در حال اجراست. کمی بعد تلاش کنید.");
    this.activeChecks.add(lock);
    try {
      return await discoverRecorders(input.cidr, input.port, input.https);
    } finally {
      this.activeChecks.delete(lock);
    }
  }

  async inspectRecorder(
    user: AppUser,
    id: string,
    profileToken?: string,
    operation: "snapshot" | "stream" = "snapshot",
  ) {
    this.writable(user);
    const device = await this.get(user, id);
    if (!["nvr", "dvr", "camera"].includes(device.type) || device.protocol !== "api")
      throw new BadRequestException("پایش فقط برای ضبط‌کننده در دسترس است.");
    if (this.activeChecks.has(id) || this.activeChecks.size >= 8)
      throw new ConflictException("تست یا عملیات دیگری در حال اجراست. کمی بعد تلاش کنید.");
    this.activeChecks.add(id);
    try {
      const snapshot = await this.devices.findOne({
        where: { id, workspaceOwnerId: device.workspaceOwnerId },
        select: { id: true, sealedRecorderCredentials: true },
      });
      if (!snapshot?.sealedRecorderCredentials)
        throw new NotFoundException("ابتدا اتصال ضبط‌کننده را تأیید و ذخیره کنید.");
      const credentials = unsealRecorderCredentials(
        device,
        snapshot.sealedRecorderCredentials,
        recorderVaultKey(),
      );
      if (credentials.mode && !["dvrip", "appweb", "onvif"].includes(credentials.mode))
        throw new BadRequestException(
          "خواندن وضعیت کانال و دیسک برای اتصال DVRIP، AppWeb و ONVIF در دسترس است.",
        );
      if (profileToken && credentials.mode && credentials.mode !== "onvif")
        throw new BadRequestException("پیش‌نمایش برای اتصال ONVIF در دسترس است.");
      try {
        if (profileToken) {
          const inspectProfile = operation === "stream" ? verifyOnvifStream : snapshotOnvif;
          return await inspectProfile(
            device.host,
            device.managementPort,
            credentials,
            profileToken,
          );
        }
        const inspect =
          credentials.mode === "appweb"
            ? inspectAppWeb
            : credentials.mode === "dvrip"
              ? inspectDvrip
              : inspectOnvif;
        return await inspect(device.host, device.managementPort, credentials);
      } catch {
        throw new BadGatewayException(
          "خواندن وضعیت ضبط‌کننده انجام نشد. اتصال ذخیره‌شده را بررسی کنید.",
        );
      }
    } finally {
      this.activeChecks.delete(id);
    }
  }

  async verifySavedRecorder(user: AppUser, id: string, input: VerifyRecorderDto) {
    this.writable(user);
    const device = await this.get(user, id);
    if (!["nvr", "dvr", "camera"].includes(device.type) || device.protocol !== "api")
      throw new BadRequestException("تأیید ONVIF فقط برای ضبط‌کننده با پروتکل API در دسترس است.");
    if (this.activeChecks.has(id) || this.activeChecks.size >= 8)
      throw new ConflictException("تست یا عملیات دیگری در حال اجراست. کمی بعد تلاش کنید.");

    this.activeChecks.add(id);
    try {
      const {
        username,
        password,
        https,
        mode: requestedMode,
        rtspPath,
        onvifPath,
        useSaved,
        saveConnection,
      } = input;
      if (
        useSaved &&
        (username !== undefined ||
          password !== undefined ||
          https !== undefined ||
          requestedMode !== undefined ||
          rtspPath !== undefined ||
          onvifPath !== undefined ||
          saveConnection)
      )
        throw new BadRequestException("حالت اتصال ذخیره‌شده را جداگانه انتخاب کنید.");
      if (!useSaved && (!username || !password || typeof https !== "boolean"))
        throw new BadRequestException("نام کاربری و گذرواژه ضبط‌کننده را وارد کنید.");
      const key = useSaved || saveConnection ? recorderVaultKey() : undefined;
      const snapshot = key
        ? await this.devices.findOne({
            where: { id, workspaceOwnerId: device.workspaceOwnerId },
            select: { id: true, sealedRecorderCredentials: true },
          })
        : undefined;
      if (useSaved && !snapshot?.sealedRecorderCredentials)
        throw new NotFoundException("اتصال ONVIF برای ضبط‌کننده ذخیره نشده است.");
      const credentials =
        useSaved && key && snapshot?.sealedRecorderCredentials
          ? unsealRecorderCredentials(device, snapshot.sealedRecorderCredentials, key)
          : {
              username: username!,
              password: password!,
              https: https!,
              mode: requestedMode,
              rtspPath,
              onvifPath,
            };
      const { identity, mode } = await verifyRecorderConnection(
        device.host,
        device.managementPort,
        this.recorderCredentials(device.type, credentials),
      );
      const verification = { identity, checkedAt: new Date().toISOString() };
      const result = await this.devices.update(
        {
          id,
          workspaceOwnerId: device.workspaceOwnerId,
          companyId: device.companyId ?? IsNull(),
          host: device.host,
          managementPort: device.managementPort,
          type: device.type,
          vendor: device.vendor,
          protocol: device.protocol,
          accessRoute: device.accessRoute,
          deletedAt: IsNull(),
          ...(key
            ? { sealedRecorderCredentials: snapshot?.sealedRecorderCredentials ?? IsNull() }
            : {}),
        },
        {
          verification,
          ...(saveConnection && key
            ? {
                sealedRecorderCredentials: sealRecorderCredentials(
                  device,
                  { ...credentials, mode },
                  key,
                ),
              }
            : {}),
        },
      );
      if (!result.affected)
        throw new ConflictException("مشخصات تجهیز تغییر کرد. اتصال را دوباره تست کنید.");
      return verification;
    } finally {
      this.activeChecks.delete(id);
    }
  }

  async linuxSsh(user: AppUser, id: string, input: LinuxSshDto) {
    this.writable(user);
    const device = await this.get(user, id);
    if (
      !["linux_edge", "mikrotik", "pfsense", "esxi", "fortigate", "cisco"].includes(device.type) ||
      device.protocol !== "ssh"
    )
      throw new BadRequestException(
        "این عملیات برای Linux، MikroTik، pfSense، ESXi، FortiGate و Cisco با پروتکل SSH در دسترس است.",
      );
    if (this.activeChecks.has(id) || this.activeChecks.size >= 8)
      throw new ConflictException("تست یا عملیات دیگری در حال اجراست. کمی بعد تلاش کنید.");

    this.activeChecks.add(id);
    try {
      const profiles = this.devices.manager.getRepository(DeviceSshProfile);
      let profile: DeviceSshProfile | null = null;
      let stored: DeviceCredential | undefined;
      let credentials: ReturnType<typeof requireSshCredentials>;
      if (input.useSaved) {
        if (
          input.saveConnection ||
          input.username ||
          input.hostKey ||
          input.privateKey ||
          input.password
        )
          throw new BadRequestException("حالت استفاده از اتصال ذخیره‌شده را جداگانه انتخاب کنید.");
        profile = await profiles.findOneBy({ deviceId: id });
        if (profile) {
          credentials = unsealSshCredentials(device, profile.sealedCredentials, sshVaultKey());
        } else if (device.credentialId) {
          stored = await this.getCredential(user, device.credentialId);
          credentials = unsealSshCredentials(
            this.credentialContext(user, stored.id),
            stored.sealedCredentials,
            sshVaultKey(),
          );
        } else {
          throw new NotFoundException("اتصال SSH برای تجهیز ثبت نشده است.");
        }
      } else {
        credentials = requireSshCredentials(input);
      }

      if (input.saveConnection && input.operation !== "verify")
        throw new BadRequestException("برای ذخیره اتصال، عملیات تأیید ورود را انتخاب کنید.");
      const key = input.saveConnection ? sshVaultKey() : undefined;
      const ciscoState = await this.ciscoAccess.augment(user, device, {
        credentials,
        revision: "direct",
      });
      const result = await runLinuxSsh(device, {
        ...ciscoState.credentials,
        operation: input.operation,
      });
      if (input.operation !== "verify") return result;

      await this.devices.manager.transaction(async (manager) => {
        const current = await manager.findOne(Device, {
          where: { id, workspaceOwnerId: device.workspaceOwnerId },
          lock: { mode: "pessimistic_write" },
        });
        if (
          !current ||
          current.host !== device.host ||
          current.managementPort !== device.managementPort ||
          current.type !== device.type ||
          current.vendor !== device.vendor ||
          current.protocol !== device.protocol ||
          current.companyId !== device.companyId ||
          current.accessRoute !== device.accessRoute ||
          current.credentialId !== device.credentialId
        )
          throw new ConflictException("مشخصات تجهیز تغییر کرد. اتصال را دوباره تست کنید.");
        const freshCisco = await this.ciscoAccess.augment(
          user,
          current,
          { credentials, revision: "direct" },
          manager,
          true,
        );
        if (freshCisco.revision !== ciscoState.revision)
          throw new ConflictException("تنظیم Cisco یا رمز enable تغییر کرد. دوباره تست کنید.");
        if (stored) {
          const latest = await manager.getRepository(DeviceCredential).findOne({
            where: { id: stored.id, ownerId: user.id },
            select: { id: true, sealedCredentials: true },
          });
          if (latest?.sealedCredentials !== stored.sealedCredentials)
            throw new ConflictException("اعتبارنامه تغییر کرد. اتصال را دوباره تست کنید.");
        }
        if (profile) {
          const latest = await manager.findOneBy(DeviceSshProfile, { deviceId: id });
          if (latest?.sealedCredentials !== profile.sealedCredentials)
            throw new ConflictException("اتصال ذخیره‌شده تغییر کرد. دوباره تست کنید.");
        }
        if (key) {
          await manager.upsert(
            DeviceSshProfile,
            {
              deviceId: id,
              sealedCredentials: sealSshCredentials(current, credentials, key),
            },
            ["deviceId"],
          );
        }
        await manager.update(Device, id, {
          verification: { checkedAt: result.checkedAt, identity: result.identity },
        });
      });
      return key ? { ...result, saved: true } : result;
    } finally {
      this.activeChecks.delete(id);
    }
  }

  managedDevice(user: AppUser, id: string) {
    this.writable(user);
    return this.get(user, id);
  }
  managementScope(user: AppUser) {
    this.writable(user);
    return this.scope(user);
  }

  private assertVendorApi(device: Pick<Device, "type" | "vendor" | "protocol">) {
    if (!vendorApiKind(device))
      throw new BadRequestException("اتصال API برای ESXi، MikroTik و Sophos در دسترس است.");
  }
  private apiIdentity(inventory: ApiInventory): Record<string, string> {
    if (inventory.kind === "mikrotik")
      return {
        Manufacturer: "MikroTik",
        Model: inventory.architecture.slice(0, 256),
        FirmwareVersion: inventory.routerosVersion.slice(0, 256),
        Hostname: inventory.identity.slice(0, 256),
      };
    if (inventory.kind === "sophos")
      return {
        Manufacturer: "Sophos",
        Model: inventory.product,
        ApiVersion: inventory.apiVersion?.slice(0, 256) ?? "",
      };
    return {
      Manufacturer: (inventory.hardwareVendor || "VMware").slice(0, 256),
      Model: inventory.model.slice(0, 256),
      FirmwareVersion: `${inventory.version} build-${inventory.build}`.slice(0, 256),
      Hostname: inventory.hostname.slice(0, 256),
    };
  }
  private async collectApi(
    device: Device,
    secret: import("./ssh-credential-vault").ApiSecret,
  ): Promise<ApiInventory> {
    try {
      return await collectVendorApi(device, secret);
    } catch (error) {
      const code =
        error instanceof EsxiSoapError || error instanceof VendorApiError
          ? error.code
          : "API_CONNECTION_FAILED";
      throw new BadGatewayException({
        message:
          "اتصال API انجام نشد. آدرس، پورت، حساب کاربری، مجوز و تنظیمات گواهی TLS را بررسی کنید.",
        code,
      });
    }
  }
  async assignApiCredential(user: AppUser, id: string, credentialId: string) {
    const workspaceOwnerId = this.managementScope(user);
    await this.devices.manager.transaction(async (manager) => {
      const device = await manager.findOne(Device, {
        where: { id, workspaceOwnerId },
        lock: { mode: "pessimistic_write" },
      });
      if (!device) throw new NotFoundException("تجهیز پیدا نشد.");
      this.assertVendorApi(device);
      await this.apiCredentials.get(user, credentialId, manager, true);
      device.apiCredentialId = credentialId;
      device.credentialId = null;
      device.verification = null;
      await manager.save(device);
    });
    return this.get(user, id);
  }
  async verifySavedApi(user: AppUser, id: string, expected?: VendorApiKind) {
    const device = await this.managedDevice(user, id);
    this.assertVendorApi(device);
    if (expected && vendorApiKind(device) !== expected)
      throw new BadRequestException("روش اتصال این تجهیز با درخواست سازگار نیست.");
    if (!device.apiCredentialId)
      throw new BadRequestException("ابتدا اعتبارنامهٔ API را انتخاب کنید.");
    if (this.activeChecks.has(id) || this.activeChecks.size >= 8)
      throw new ConflictException("تست یا گردآوری دیگری در حال اجراست. کمی بعد تلاش کنید.");
    this.activeChecks.add(id);
    try {
      const stored = await this.apiCredentials.get(user, device.apiCredentialId);
      const binding = this.verificationBinding(user, device, device.companyId!, stored);
      const inventory = await this.collectApi(device, this.apiCredentials.secret(user, stored));
      await this.devices.manager.transaction(async (manager) => {
        const actor = await manager.findOneBy(AppUser, { id: user.id });
        if (!actor?.isActive || this.scope(actor) !== device.workspaceOwnerId)
          throw new ForbiddenException("دسترسی به تجهیز تغییر کرده است.");
        this.writable(actor);
        const current = await manager.findOne(Device, {
          where: { id, workspaceOwnerId: device.workspaceOwnerId },
          lock: { mode: "pessimistic_write" },
        });
        if (!current?.apiCredentialId) throw new ConflictException("اتصال تجهیز تغییر کرده است.");
        const credential = await this.apiCredentials.get(
          actor,
          current.apiCredentialId,
          manager,
          true,
        );
        if (binding !== this.verificationBinding(actor, current, current.companyId!, credential))
          throw new ConflictException(
            "تجهیز یا اعتبارنامه هنگام گردآوری تغییر کرد. دوباره تلاش کنید.",
          );
        current.verification = {
          checkedAt: inventory.collectedAt,
          identity: this.apiIdentity(inventory),
        };
        await manager.save(current);
      });
      return inventory;
    } finally {
      this.activeChecks.delete(id);
    }
  }

  async verifySavedEsxiSsh(user: AppUser, id: string) {
    const device = await this.managedDevice(user, id);
    if (device.type !== "esxi" || device.protocol !== "ssh")
      throw new BadRequestException("این عملیات به تجهیز ESXi با اتصال SSH نیاز دارد.");
    if (this.activeChecks.has(id) || this.activeChecks.size >= 8)
      throw new ConflictException("گردآوری دیگری در حال اجراست. کمی بعد تلاش کنید.");
    this.activeChecks.add(id);
    try {
      const snapshot = await this.savedSshCredentialSnapshot(user, device);
      const bind = (actor: AppUser, target: Device, revision: string) =>
        this.verificationBinding(actor, target, target.companyId!, {
          id: target.id,
          sealedCredentials: revision,
        });
      const binding = bind(user, device, snapshot.revision);
      let inventory: Awaited<ReturnType<typeof collectEsxiSshInventory>>;
      try {
        inventory = await collectEsxiSshInventory(device, snapshot.credentials);
      } catch (error) {
        throw new BadGatewayException({
          message:
            "موجودی ESXi دریافت نشد. مقصد، حساب SSH، کلید میزبان و مجوز فرمان‌های خواندنی را بررسی کنید.",
          code: error instanceof EsxiSoapError ? error.code : "ESXI_SSH_COLLECTION_FAILED",
        });
      }
      await this.devices.manager.transaction(async (manager) => {
        const actor = await manager.findOne(AppUser, {
          where: { id: user.id },
          lock: { mode: "pessimistic_read" },
        });
        if (!actor?.isActive || this.managementScope(actor) !== device.workspaceOwnerId)
          throw new ForbiddenException("دسترسی به تجهیز تغییر کرده است.");
        const current = await manager.findOne(Device, {
          where: { id, workspaceOwnerId: device.workspaceOwnerId },
          lock: { mode: "pessimistic_write" },
        });
        if (!current || current.type !== "esxi" || current.protocol !== "ssh")
          throw new ConflictException("اتصال تجهیز تغییر کرده است.");
        const fresh = await this.savedSshCredentialSnapshot(actor, current, manager, true);
        if (binding !== bind(actor, current, fresh.revision))
          throw new ConflictException(
            "تجهیز یا اعتبارنامه هنگام گردآوری تغییر کرد. دوباره تلاش کنید.",
          );
        current.verification = {
          checkedAt: inventory.collectedAt,
          identity: {
            Manufacturer: "VMware",
            FirmwareVersion: inventory.version,
            Model: inventory.model.slice(0, 256),
          },
        };
        await manager.save(current);
      });
      return inventory;
    } finally {
      this.activeChecks.delete(id);
    }
  }

  async librarySshCredentials(user: AppUser, id: string) {
    this.scope(user);
    const stored = await this.getCredential(user, id);
    return unsealSshCredentials(
      this.credentialContext(user, stored.id),
      stored.sealedCredentials,
      sshVaultKey(),
    );
  }

  async savedSshCredentials(
    user: AppUser,
    device: Device,
    manager = this.devices.manager,
    lock = false,
  ) {
    return (await this.savedSshCredentialSnapshot(user, device, manager, lock)).credentials;
  }
  async savedSshCredentialSnapshot(
    user: AppUser,
    device: Device,
    manager = this.devices.manager,
    lock = false,
  ) {
    const profile = await manager.findOne(DeviceSshProfile, {
      where: { deviceId: device.id },
      ...(lock ? { lock: { mode: "pessimistic_read" as const } } : {}),
    });
    if (profile)
      return this.ciscoAccess.augment(
        user,
        device,
        {
          credentials: unsealSshCredentials(device, profile.sealedCredentials, sshVaultKey()),
          revision: profile.sealedCredentials,
        },
        manager,
        lock,
      );
    if (device.credentialId) {
      const entry = await manager.getRepository(DeviceCredential).findOne({
        where: { id: device.credentialId, ownerId: user.id },
        select: { id: true, sealedCredentials: true },
        ...(lock ? { lock: { mode: "pessimistic_read" as const } } : {}),
      });
      if (!entry) throw new NotFoundException("اعتبارنامه پیدا نشد.");
      return this.ciscoAccess.augment(
        user,
        device,
        {
          credentials: unsealSshCredentials(
            this.credentialContext(user, entry.id),
            entry.sealedCredentials,
            sshVaultKey(),
          ),
          revision: entry.id + entry.sealedCredentials,
        },
        manager,
        lock,
      );
    }
    throw new NotFoundException("ابتدا اتصال SSH یا اعتبارنامهٔ تجهیز را ذخیره کنید.");
  }

  async inventoryEvents(user: AppUser, id: string) {
    const device = await this.get(user, id);
    return this.devices.manager.query(
      `SELECT "id", "action", "actorName", "occurredAt" FROM "device_inventory_events"
       WHERE "deviceId" = $1 ORDER BY "occurredAt" DESC, "id" DESC LIMIT 100`,
      [device.id],
    );
  }

  private async recordInventoryEvent(
    manager: Repository<Device>["manager"],
    user: AppUser,
    id: string,
    action: "archived" | "restored" | "transferred",
  ) {
    await manager.query(
      `INSERT INTO "device_inventory_events" ("deviceId", "actorName", "action") VALUES ($1, $2, $3)`,
      [id, user.displayName, action],
    );
  }

  async restore(user: AppUser, id: string) {
    this.writable(user);
    try {
      await this.devices.manager.transaction(async (manager) => {
        const result = await manager.getRepository(Device).restore({
          id,
          workspaceOwnerId: this.scope(user),
          deletedAt: Not(IsNull()),
        });
        if (!result.affected) throw new NotFoundException("تجهیز بایگانی‌شده پیدا نشد.");
        await this.recordInventoryEvent(manager, user, id, "restored");
      });
    } catch (error) {
      if (error instanceof QueryFailedError && error.driverError.code === "23505")
        throw new ConflictException("تجهیز فعالی با همین سازنده، آدرس، پورت و پروتکل وجود دارد.");
      throw error;
    }
    return { message: "تجهیز به فهرست فعال برگشت." };
  }

  async archive(user: AppUser, id: string) {
    this.writable(user);
    await this.devices.manager.transaction(async (manager) => {
      const result = await manager.getRepository(Device).softDelete({
        id,
        workspaceOwnerId: this.scope(user),
        deletedAt: IsNull(),
      });
      if (!result.affected) throw new NotFoundException("تجهیز پیدا نشد.");
      await manager.query(
        `UPDATE "device_monitoring" SET "enabled"=false,"nextRunAt"=NULL,"leaseToken"=NULL,"leaseExpiresAt"=NULL,"revision"=$2 WHERE "deviceId"=$1`,
        [id, randomUUID()],
      );
      await manager.query(
        `UPDATE device_capability_cache SET "binding"=NULL,"expiresAt"=NULL,"leaseToken"=NULL,"leaseExpiresAt"=NULL WHERE "deviceId"=$1`,
        [id],
      );
      await this.recordInventoryEvent(manager, user, id, "archived");
    });
    return { message: "تجهیز از فهرست فعال بایگانی شد." };
  }
}
