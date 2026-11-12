import type { ResolvedMonitorSource } from "./monitoring.types";
import { collectVendorApi, type ApiInventory } from "./vendor-api-collector";
import { VendorApiError } from "./vendor-https";
import { EsxiSoapError } from "./esxi-soap";
import { DeviceApiCredential } from "./vendor-api-credential.entity";
import { vendorApiKind } from "./vendor-api-kind";
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from "@nestjs/common";
import { DataSource, EntityManager } from "typeorm";
import { createHmac, randomUUID } from "node:crypto";
import { AppUser } from "../users/user.entity";
import { Device } from "./device.entity";
import { DeviceCredential } from "./device-onboarding.entity";
import {
  DeviceSecondaryChannel,
  DeviceSnmpCredential,
  type SecondaryChannelMethod,
} from "./device-channels.entity";
import {
  SaveSecondaryChannelDto,
  SaveSnmpCredentialDto,
  ToggleSecondaryChannelDto,
} from "./device-channels.dto";
import { DevicesService } from "./devices.service";
import {
  sealSnmpCredentials,
  unsealSnmpCredentials,
  unsealSshCredentials,
  unsealApiCredentials,
  type ApiSecret,
  sshVaultKey,
} from "./ssh-credential-vault";
import { pollSnmpv3, type SnmpSecret } from "./snmpv3";
import { runLinuxSsh, type SshCredentials } from "./linux-ssh";

@Injectable()
export class DeviceChannelsService {
  private readonly running = new Set<string>();
  constructor(
    private readonly db: DataSource,
    private readonly devices: DevicesService,
  ) {}
  private workspace(user: AppUser) {
    if (user.allowedSections.length && !user.allowedSections.includes("assets"))
      throw new ForbiddenException("به دارایی‌ها دسترسی ندارید.");
    return user.workspaceOwnerId ?? user.id;
  }
  credentials(user: AppUser) {
    this.workspace(user);
    return this.db
      .getRepository(DeviceSnmpCredential)
      .find({ where: { ownerId: user.id }, order: { name: "ASC" } });
  }
  async saveCredential(
    user: AppUser,
    input: SaveSnmpCredentialDto,
    id: string = randomUUID(),
    editing = false,
  ) {
    this.workspace(user);
    const row = {
      id,
      ownerId: user.id,
      name: input.name,
      username: input.username,
      authProtocol: input.authProtocol,
      sealedCredentials: sealSnmpCredentials(user.id, id, {
        username: input.username,
        authProtocol: input.authProtocol,
        authPassword: input.authPassword,
        privacyPassword: input.privacyPassword,
      }),
    };
    if (editing) {
      const result = await this.db
        .getRepository(DeviceSnmpCredential)
        .update({ id, ownerId: user.id }, row);
      if (!result.affected) throw new NotFoundException("اعتبارنامه پیدا نشد.");
    } else await this.db.getRepository(DeviceSnmpCredential).insert(row);
    return { id, name: row.name, username: row.username, authProtocol: row.authProtocol };
  }
  async deleteCredential(user: AppUser, id: string) {
    this.workspace(user);
    const result = await this.db
      .getRepository(DeviceSnmpCredential)
      .delete({ id, ownerId: user.id });
    if (!result.affected) throw new NotFoundException("اعتبارنامه پیدا نشد.");
    return { deleted: true };
  }
  private async lockedDevice(manager: EntityManager, user: AppUser, id: string) {
    const current = await manager.findOne(AppUser, {
      where: { id: user.id },
      lock: { mode: "pessimistic_read" },
    });
    if (!current?.isActive) throw new ForbiddenException("حساب کاربری غیرفعال است.");
    const workspaceOwnerId = this.devices.managementScope(current);
    if (workspaceOwnerId !== this.workspace(user))
      throw new ForbiddenException("فضای کاری تغییر کرده است.");
    const device = await manager.findOne(Device, {
      where: { id, workspaceOwnerId },
      lock: { mode: "pessimistic_write" },
    });
    if (!device) throw new NotFoundException("تجهیز پیدا نشد.");
    return device;
  }
  private availableMethods(device: Device): SecondaryChannelMethod[] {
    if (device.type === "esxi" && device.protocol === "api") return ["ssh", "snmpv3"];
    if (device.type === "esxi" && device.protocol === "ssh") return ["soap_api", "snmpv3"];
    if (device.type === "mikrotik" && device.protocol === "ssh") return ["snmpv3", "rest_api"];
    return ["cisco", "fortigate", "mikrotik", "esxi", "pfsense", "generic_firewall"].includes(
      device.type,
    )
      ? ["snmpv3"]
      : [];
  }
  private assertMethod(device: Device, method: SecondaryChannelMethod) {
    if (!this.availableMethods(device).includes(method))
      throw new BadRequestException("روش انتخاب‌شده برای کانال ثانویهٔ این تجهیز در دسترس نیست.");
  }
  private async snapshot(
    manager: EntityManager,
    user: AppUser,
    device: Device,
    channel: DeviceSecondaryChannel,
    lock = false,
  ) {
    const api = channel.method === "soap_api" || channel.method === "rest_api";
    const id = api
      ? channel.apiCredentialId
      : channel.method === "ssh"
        ? channel.credentialId
        : channel.snmpCredentialId;
    if (!id) throw new NotFoundException("اعتبارنامهٔ کانال را انتخاب کنید.");
    const repo = manager.getRepository(
      api
        ? DeviceApiCredential
        : channel.method === "ssh"
          ? DeviceCredential
          : DeviceSnmpCredential,
    );
    const row = await repo.findOne({
      where: { id, ownerId: user.id },
      select: { id: true, sealedCredentials: true },
      ...(lock ? { lock: { mode: "pessimistic_read" as const } } : {}),
    });
    if (!row) throw new NotFoundException("اعتبارنامهٔ این کانال در حساب شما موجود نیست.");
    const binding = createHmac("sha256", sshVaultKey())
      .update(
        JSON.stringify([
          device.id,
          device.workspaceOwnerId,
          device.companyId,
          device.host,
          device.managementPort,
          device.protocol,
          device.type,
          device.vendor,
          channel.revision,
          channel.host,
          channel.port,
          channel.method,
          row.id,
          row.sealedCredentials,
        ]),
      )
      .digest("hex");
    const secret = api
      ? unsealApiCredentials(user.id, id, row.sealedCredentials)
      : channel.method === "ssh"
        ? unsealSshCredentials(
            { id, workspaceOwnerId: user.id, host: "credential-library", managementPort: 0 },
            row.sealedCredentials,
            sshVaultKey(),
          )
        : unsealSnmpCredentials(user.id, id, row.sealedCredentials);
    return { binding, secret };
  }
  private channel(manager: EntityManager, deviceId: string) {
    return manager.getRepository(DeviceSecondaryChannel).findOne({
      where: { deviceId },
      select: {
        deviceId: true,
        method: true,
        credentialId: true,
        snmpCredentialId: true,
        apiCredentialId: true,
        host: true,
        port: true,
        enabled: true,
        priority: true,
        revision: true,
        status: true,
        verifiedBinding: true,
        testToken: true,
        testExpiresAt: true,
        lastTestAt: true,
        lastSuccessAt: true,
        lastError: true,
        telemetry: true,
      },
    });
  }
  async monitoringSource(
    user: AppUser,
    device: Device,
    manager: EntityManager = this.db.manager,
    lock = false,
  ): Promise<(ResolvedMonitorSource & { priority: number }) | null> {
    const channel = await this.channel(manager, device.id);
    if (
      !channel?.enabled ||
      channel.status !== "verified" ||
      !this.availableMethods(device).includes(channel.method)
    )
      return null;
    const snapshot = await this.snapshot(manager, user, device, channel, lock);
    if (snapshot.binding !== channel.verifiedBinding) return null;
    const target = Object.assign(new Device(), device, {
      host: channel.host || device.host,
      managementPort: channel.port,
      protocol: channel.method === "ssh" ? "ssh" : "api",
    });
    return {
      source: {
        role: "observability",
        method: channel.method,
        host: target.host,
        port: channel.port,
      },
      device: target,
      credentials: snapshot.secret,
      binding: snapshot.binding,
      priority: channel.priority,
    };
  }
  async list(user: AppUser, id: string) {
    const device = await this.devices.get(user, id);
    const channel = await this.channel(this.db.manager, id);
    let valid = false,
      ownCredential = false;
    if (channel) {
      try {
        const snapshot = await this.snapshot(this.db.manager, user, device, channel);
        ownCredential = true;
        valid = snapshot.binding === channel.verifiedBinding;
      } catch {
        /* Never expose another account's credential or a secret. */
      }
    }
    const recorder = ["camera", "nvr", "dvr"].includes(device.type) && device.protocol === "api";
    const primarySupported =
      (device.protocol === "ssh" &&
        ["linux_edge", "mikrotik", "pfsense", "esxi", "fortigate", "cisco"].includes(
          device.type,
        )) ||
      recorder ||
      !!vendorApiKind(device);
    const secondary = channel
      ? {
          method: channel.method,
          host: channel.host,
          port: channel.port,
          priority: channel.priority,
          revision: channel.revision,
          credentialId: ownCredential
            ? (channel.apiCredentialId ?? channel.credentialId ?? channel.snmpCredentialId)
            : null,
          enabled: channel.enabled && valid,
          status: valid ? channel.status : "configured",
          needsCredential: !ownCredential,
          lastTestAt: channel.lastTestAt,
          lastSuccessAt: channel.lastSuccessAt,
          lastError: valid ? channel.lastError : null,
          telemetry: valid ? channel.telemetry : null,
          testing: !!channel.testExpiresAt && channel.testExpiresAt.getTime() > Date.now(),
        }
      : null;
    const history = await this.db.query(
      `SELECT "id", "method", "connected", "errorCode", "checkedAt" FROM "device_channel_tests" WHERE "deviceId"=$1 ORDER BY "checkedAt" DESC,"id" DESC LIMIT 5`,
      [id],
    );
    return {
      primary: {
        method: device.protocol,
        host: device.host,
        port: device.managementPort,
        supported: primarySupported,
        credentialsConfigured: vendorApiKind(device) ? !!device.apiCredentialId : undefined,
        status: device.verification ? "verified" : "configured",
        priority: secondary?.enabled && secondary.priority === 1 ? 2 : 1,
        lastSuccessAt: device.verification?.checkedAt ?? null,
      },
      secondary,
      availableMethods: this.availableMethods(device),
      preferred:
        secondary?.enabled && (secondary.priority === 1 || !device.verification)
          ? "observability"
          : device.verification
            ? "management"
            : null,
      history,
    };
  }
  async configure(user: AppUser, id: string, input: SaveSecondaryChannelDto) {
    await this.db.transaction(async (manager) => {
      const device = await this.lockedDevice(manager, user, id);
      this.assertMethod(device, input.method);
      const previous = await this.channel(manager, id);
      if ((previous && previous.revision !== input.revision) || (!previous && input.revision))
        throw new ConflictException("تنظیمات کانال تغییر کرده است. صفحه را تازه کنید.");
      const row = manager.create(DeviceSecondaryChannel, {
        deviceId: id,
        method: input.method,
        credentialId: input.method === "ssh" ? input.credentialId : null,
        snmpCredentialId: input.method === "snmpv3" ? input.credentialId : null,
        apiCredentialId: ["soap_api", "rest_api"].includes(input.method)
          ? input.credentialId
          : null,
        host: input.host ?? null,
        port: input.port,
        priority: input.priority,
        enabled: false,
        status: "configured",
        revision: randomUUID(),
        verifiedBinding: null,
        testToken: null,
        testExpiresAt: null,
        lastTestAt: null,
        lastSuccessAt: null,
        lastError: null,
        telemetry: null,
      });
      await this.snapshot(manager, user, device, row, true);
      await manager.save(row);
    });
    return this.list(user, id);
  }
  async toggle(user: AppUser, id: string, input: ToggleSecondaryChannelDto) {
    await this.db.transaction(async (manager) => {
      const device = await this.lockedDevice(manager, user, id),
        channel = await this.channel(manager, id);
      if (!channel || channel.revision !== input.revision)
        throw new ConflictException("تنظیمات کانال تغییر کرده است. صفحه را تازه کنید.");
      if (channel.testExpiresAt && channel.testExpiresAt.getTime() > Date.now())
        throw new ConflictException("تست کانال در حال اجراست.");
      if (
        input.enabled &&
        ((await this.snapshot(manager, user, device, channel, true)).binding !==
          channel.verifiedBinding ||
          channel.status !== "verified")
      )
        throw new ConflictException("ابتدا اتصال با تنظیمات فعلی را تست کنید.");
      channel.enabled = input.enabled;
      await manager.save(channel);
    });
    return this.list(user, id);
  }
  async testPrimary(user: AppUser, id: string) {
    const device = await this.devices.managedDevice(user, id);
    if (device.protocol === "ssh")
      await this.devices.linuxSsh(user, id, { useSaved: true, operation: "verify" });
    else if (vendorApiKind(device)) await this.devices.verifySavedApi(user, id);
    else if (["camera", "nvr", "dvr"].includes(device.type) && device.protocol === "api")
      await this.devices.verifySavedRecorder(user, id, { useSaved: true });
    else throw new BadRequestException("تست این روش مدیریتی هنوز منتقل نشده است.");
    return { connected: true };
  }
  async testSecondary(user: AppUser, id: string) {
    if (this.running.has(id)) throw new ConflictException("تست کانال در حال اجراست.");
    if (this.running.size >= 8)
      throw new ServiceUnavailableException("ظرفیت تست پر است. کمی بعد تلاش کنید.");
    this.running.add(id);
    const token = randomUUID();
    try {
      const initial = await this.db.transaction(async (manager) => {
        const device = await this.lockedDevice(manager, user, id),
          channel = await this.channel(manager, id);
        if (!channel) throw new NotFoundException("ابتدا کانال ثانویه را تنظیم کنید.");
        this.assertMethod(device, channel.method);
        if (channel.testExpiresAt && channel.testExpiresAt.getTime() > Date.now())
          throw new ConflictException("تست کانال در حال اجراست.");
        const snapshot = await this.snapshot(manager, user, device, channel, true);
        channel.testToken = token;
        channel.testExpiresAt = new Date(
          Date.now() + (["soap_api", "rest_api"].includes(channel.method) ? 210000 : 90000),
        );
        await manager.save(channel);
        return { device, channel, ...snapshot };
      });
      let inventory: ApiInventory | undefined;
      let checkedAt: string | undefined;
      let connected = false,
        errorCode: string | null = null,
        telemetry: DeviceSecondaryChannel["telemetry"] = null;
      try {
        const host = initial.channel.host ?? initial.device.host;
        if (initial.channel.method === "snmpv3")
          telemetry = await pollSnmpv3(host, initial.channel.port, initial.secret as SnmpSecret);
        else if (["soap_api", "rest_api"].includes(initial.channel.method))
          inventory = await collectVendorApi(
            { ...initial.device, host, managementPort: initial.channel.port, protocol: "api" },
            initial.secret as ApiSecret,
          );
        else
          await runLinuxSsh(
            { ...initial.device, host, managementPort: initial.channel.port, protocol: "ssh" },
            { ...(initial.secret as SshCredentials), operation: "verify" },
          );
        connected = true;
      } catch (error) {
        errorCode =
          error instanceof EsxiSoapError || error instanceof VendorApiError
            ? error.code
            : error instanceof Error &&
                ["SNMP_TIMEOUT", "SNMP_AUTH_OR_QUERY_FAILED", "SNMP_INVALID_RESPONSE"].includes(
                  error.message,
                )
              ? error.message
              : initial.channel.method === "ssh"
                ? "SSH_CONNECTION_FAILED"
                : initial.channel.method === "snmpv3"
                  ? "SNMP_AUTH_OR_QUERY_FAILED"
                  : "API_CONNECTION_FAILED";
      }
      await this.db.transaction(async (manager) => {
        const device = await this.lockedDevice(manager, user, id),
          channel = await this.channel(manager, id);
        if (
          !channel ||
          channel.testToken !== token ||
          (await this.snapshot(manager, user, device, channel, true)).binding !== initial.binding
        )
          throw new ConflictException("تجهیز یا اعتبارنامه هنگام تست تغییر کرد؛ نتیجه ثبت نشد.");
        channel.testToken = null;
        channel.testExpiresAt = null;
        channel.lastTestAt = new Date();
        checkedAt = channel.lastTestAt.toISOString();
        channel.lastError = errorCode;
        channel.status = connected ? "verified" : "error";
        channel.enabled = connected;
        channel.verifiedBinding = initial.binding;
        channel.telemetry = telemetry;
        if (connected) channel.lastSuccessAt = channel.lastTestAt;
        await manager.save(channel);
        await manager.query(
          `INSERT INTO "device_channel_tests" ("deviceId","method","connected","errorCode","actorId") VALUES ($1,$2,$3,$4,$5)`,
          [id, channel.method, connected, errorCode, user.id],
        );
        await manager.query(
          `DELETE FROM "device_channel_tests" WHERE "deviceId"=$1 AND "id" NOT IN (SELECT "id" FROM "device_channel_tests" WHERE "deviceId"=$1 ORDER BY "checkedAt" DESC,"id" DESC LIMIT 5)`,
          [id],
        );
      });
      return { connected, errorCode, inventory, revision: initial.channel.revision, checkedAt };
    } finally {
      try {
        await this.db.query(
          `UPDATE "device_secondary_channels" SET "testToken"=NULL,"testExpiresAt"=NULL WHERE "deviceId"=$1 AND "testToken"=$2`,
          [id, token],
        );
      } finally {
        this.running.delete(id);
      }
    }
  }
}
