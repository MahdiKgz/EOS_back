import {
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
import { DevicesService } from "./devices.service";
import { DeviceChannelsService } from "./device-channels.service";
import { VendorApiCredentialsService } from "./vendor-api-credentials.service";
import { DeviceMonitoring } from "./device-monitoring.entity";
import { SaveMonitoringDto, MonitoringQueryDto } from "./monitoring.dto";
import { sshVaultKey, type ApiSecret } from "./ssh-credential-vault";
import { vendorApiKind } from "./vendor-api-kind";
import { collectVendorApi } from "./vendor-api-collector";
import type { SnmpSecret } from "./snmpv3";
import { collectSnmpMonitoring } from "./monitoring-snmp";
import type { SshCredentials } from "./linux-ssh";
import { collectSshMonitoring } from "./monitoring-ssh";
import { apiMeasurements } from "./monitoring-measurements";
import { metricSeries, storeMeasurements, type MetricRow } from "./monitoring-storage";
import type { Measurement, ResolvedMonitorSource } from "./monitoring.types";
const sshTypes = ["linux_edge", "mikrotik", "cisco", "fortigate", "esxi", "pfsense"];
@Injectable()
export class DeviceMonitoringService {
  private readonly running = new Set<string>();
  constructor(
    private readonly db: DataSource,
    private readonly devices: DevicesService,
    private readonly channels: DeviceChannelsService,
    private readonly api: VendorApiCredentialsService,
  ) {}
  private async actor(manager: EntityManager, user: AppUser, lock = false) {
    const fresh = await manager.findOne(AppUser, {
      where: { id: user.id },
      ...(lock ? { lock: { mode: "pessimistic_read" as const } } : {}),
    });
    if (
      !fresh?.isActive ||
      this.devices.managementScope(fresh) !== (user.workspaceOwnerId ?? user.id)
    )
      throw new ForbiddenException("دسترسی مدیریت دارایی‌ها تغییر کرده است.");
    return fresh;
  }
  private async parent(manager: EntityManager, user: AppUser, id: string, lock = false) {
    const device = await manager.findOne(Device, {
      where: { id, workspaceOwnerId: user.workspaceOwnerId ?? user.id },
      ...(lock ? { lock: { mode: "pessimistic_write" as const } } : {}),
    });
    if (!device) throw new NotFoundException("تجهیز فعال پیدا نشد.");
    return device;
  }
  private async sources(manager: EntityManager, user: AppUser, device: Device, lock = false) {
    const result: ResolvedMonitorSource[] = [];
    let secondary: Awaited<ReturnType<DeviceChannelsService["monitoringSource"]>> = null;
    try {
      secondary = await this.channels.monitoringSource(user, device, manager, lock);
    } catch {
      /* Unavailable private credential is not usable for this actor. */
    }
    try {
      let credentials: ApiSecret | SshCredentials | undefined;
      let credentialRevision = "";
      if (vendorApiKind(device) && device.apiCredentialId) {
        const entry = await this.api.get(user, device.apiCredentialId, manager, lock);
        credentials = this.api.secret(user, entry);
        credentialRevision = entry.id + entry.sealedCredentials;
      } else if (device.protocol === "ssh" && sshTypes.includes(device.type)) {
        const snapshot = await this.devices.savedSshCredentialSnapshot(user, device, manager, lock);
        credentials = snapshot.credentials;
        credentialRevision = snapshot.revision;
      }
      if (credentials) {
        const binding = createHmac("sha256", sshVaultKey())
          .update(
            JSON.stringify([
              device.id,
              device.workspaceOwnerId,
              device.companyId,
              device.host,
              device.managementPort,
              device.type,
              device.vendor,
              device.protocol,
              credentialRevision,
            ]),
          )
          .digest("hex");
        result.push({
          device,
          credentials,
          binding,
          source: {
            role: "management",
            method: device.protocol === "ssh" ? "ssh" : "api",
            host: device.host,
            port: device.managementPort,
          },
        });
      }
    } catch {
      /* A secondary channel can remain usable independently of primary. */
    }
    if (secondary) {
      if (secondary.priority === 1) result.unshift(secondary);
      else result.push(secondary);
    }
    return result;
  }
  private async ensure(manager: EntityManager, user: AppUser, id: string) {
    await manager
      .createQueryBuilder()
      .insert()
      .into(DeviceMonitoring)
      .values({
        deviceId: id,
        actorId: user.id,
        enabled: false,
        intervalSeconds: 300,
        revision: randomUUID(),
        failures: 0,
      })
      .orIgnore()
      .execute();
    return await manager.findOneByOrFail(DeviceMonitoring, { deviceId: id });
  }
  async configure(user: AppUser, id: string, input: SaveMonitoringDto) {
    await this.db.transaction(async (manager) => {
      const actor = await this.actor(manager, user, true),
        device = await this.parent(manager, actor, id, true),
        existing = await manager.findOneBy(DeviceMonitoring, { deviceId: id }),
        config = existing ?? (await this.ensure(manager, actor, id));
      if ((existing && input.revision !== config.revision) || (!existing && input.revision))
        throw new ConflictException("تنظیمات پایش تغییر کرده است. دوباره دریافت کنید.");
      const sources = await this.sources(manager, actor, device, true);
      if (input.enabled && !sources.length)
        throw new BadRequestException(
          "ابتدا اعتبارنامهٔ اتصال اصلی یا کانال ثانویهٔ تأییدشده را انتخاب کنید.",
        );
      await manager.update(
        DeviceMonitoring,
        { deviceId: id },
        {
          actorId: actor.id,
          authorizedBindings: sources.map((s) => s.binding),
          enabled: input.enabled,
          intervalSeconds: input.intervalSeconds,
          revision: randomUUID(),
          nextRunAt: input.enabled ? new Date() : null,
          leaseToken: null,
          leaseExpiresAt: null,
          failures: 0,
        },
      );
    });
    return this.report(user, id, new MonitoringQueryDto());
  }
  async collect(user: AppUser, id: string, scheduled = false) {
    if (this.running.has(id)) throw new ConflictException("پایش این تجهیز در حال اجراست.");
    if (this.running.size >= 4)
      throw new ServiceUnavailableException("ظرفیت پایش پر است. کمی بعد تلاش کنید.");
    this.running.add(id);
    const token = randomUUID(),
      startedAt = new Date();
    let revision: string | null = null,
      sources: ResolvedMonitorSource[] = [];
    try {
      await this.db.transaction(async (manager) => {
        const actor = await this.actor(manager, user, true);
        const device = await this.parent(manager, actor, id, true);
        const config = await this.ensure(manager, actor, id);
        if (
          scheduled &&
          (!config.enabled ||
            config.actorId !== actor.id ||
            !config.nextRunAt ||
            config.nextRunAt > new Date())
        )
          throw new ConflictException("پایش دوره‌ای اکنون سررسید نشده است.");
        if (config.leaseExpiresAt && config.leaseExpiresAt > new Date())
          throw new ConflictException("پایش این تجهیز در حال اجراست.");
        sources = await this.sources(manager, actor, device, true);
        if (scheduled && sources.some((s) => !config.authorizedBindings.includes(s.binding)))
          throw new BadRequestException("اتصال پایش تغییر کرده است. تنظیمات را دوباره ذخیره کنید.");
        if (!sources.length)
          throw new BadRequestException("اعتبارنامهٔ قابل استفاده برای پایش وجود ندارد.");
        revision = config.revision;
        await manager.update(
          DeviceMonitoring,
          { deviceId: id },
          {
            leaseToken: token,
            leaseExpiresAt: new Date(Date.now() + 240000),
            lastAttemptAt: startedAt,
          },
        );
      });
      let selected: ResolvedMonitorSource | null = null,
        measurements: Measurement[] = [];
      const warnings: string[] = [];
      for (const source of sources) {
        try {
          if (source.source.method === "snmpv3") {
            const result = await collectSnmpMonitoring(
              source.source.host,
              source.source.port,
              source.credentials as SnmpSecret,
            );
            measurements = result.measurements;
            warnings.push(...result.warnings);
          } else if (source.source.method === "ssh") {
            const result = await collectSshMonitoring(
              source.device,
              source.credentials as SshCredentials,
            );
            measurements = result.measurements;
            warnings.push(...result.warnings);
          } else
            measurements = apiMeasurements(
              await collectVendorApi(source.device, source.credentials as ApiSecret),
            );
          if (!measurements.length) throw new Error("MONITOR_NO_METRICS");
          selected = source;
          break;
        } catch {
          measurements = [];
          warnings.push("PREFERRED_SOURCE_UNAVAILABLE");
        }
      }
      const completedAt = new Date();
      await this.db.transaction(async (manager) => {
        const actor = await this.actor(manager, user, true),
          current = await this.parent(manager, actor, id, true),
          config = await manager.findOneByOrFail(DeviceMonitoring, { deviceId: id });
        if (
          config.revision !== revision ||
          config.leaseToken !== token ||
          !config.leaseExpiresAt ||
          config.leaseExpiresAt < completedAt
        )
          throw new ConflictException("تنظیمات یا تجهیز حین پایش تغییر کرد. نتیجه ثبت نشد.");
        const fresh = await this.sources(manager, actor, current, true);
        if (
          !fresh.length ||
          (selected && !fresh.some((s) => s.binding === selected.binding)) ||
          (!selected && sources.some((s) => !fresh.some((f) => f.binding === s.binding)))
        )
          throw new ConflictException("اعتبارنامه یا اتصال حین پایش تغییر کرد. دوباره تلاش کنید.");
        if (selected) {
          const oldUptime = config.latest?.measurements.find(
              (m) => m.key === "system.uptime_seconds",
            )?.value,
            newUptime = measurements.find((m) => m.key === "system.uptime_seconds")?.value;
          const previousCounters = new Map(
            config.latest?.measurements
              .filter((m) => m.kind === "counter")
              .map((m) => [m.key + "\0" + m.label, m.value]) ?? [],
          );
          const counterReset = measurements.some(
            (m) =>
              m.kind === "counter" &&
              previousCounters.has(m.key + "\0" + m.label) &&
              m.value < previousCounters.get(m.key + "\0" + m.label)!,
          );
          const reset =
            counterReset ||
            config.generation !== selected.binding ||
            (oldUptime !== undefined && newUptime !== undefined && newUptime < oldUptime);
          const epoch = reset || !config.counterEpoch ? randomUUID() : config.counterEpoch;
          await storeMeasurements(
            manager,
            id,
            current.companyId,
            selected.binding,
            epoch,
            completedAt.toISOString(),
            measurements,
          );
          await manager.update(
            DeviceMonitoring,
            { deviceId: id },
            {
              generation: selected.binding,
              counterEpoch: epoch,
              latest: {
                actorId: actor.id,
                measurements,
                warnings,
                source: selected.source,
                collectedAt: completedAt.toISOString(),
                binding: selected.binding,
                companyId: current.companyId,
              },
              lastSuccessAt: completedAt,
              lastErrorCode: null,
              failures: 0,
              nextRunAt: config.enabled
                ? new Date(+completedAt + config.intervalSeconds * 1000)
                : null,
            },
          );
        } else
          await manager.update(
            DeviceMonitoring,
            { deviceId: id },
            {
              lastErrorCode: "MONITOR_CONNECTION_FAILED",
              failures: config.failures + 1,
              nextRunAt: config.enabled
                ? new Date(
                    +completedAt +
                      Math.min(
                        3600,
                        config.intervalSeconds * 2 ** Math.min(config.failures + 1, 6),
                      ) *
                        1000,
                  )
                : null,
            },
          );
        await manager.query(
          `INSERT INTO "device_monitor_runs" ("id","deviceId","companyId","actorId","status","source","startedAt","completedAt","errorCode","measurementCount","warnings") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
          [
            randomUUID(),
            id,
            current.companyId,
            actor.id,
            selected ? "success" : "failed",
            selected ? JSON.stringify(selected.source) : null,
            startedAt,
            completedAt,
            selected ? null : "MONITOR_CONNECTION_FAILED",
            measurements.length,
            JSON.stringify(warnings),
          ],
        );
        await manager.query(
          `DELETE FROM "device_monitor_runs" WHERE "deviceId"=$1 AND ("completedAt"<now()-interval '30 days' OR "id" NOT IN (SELECT "id" FROM "device_monitor_runs" WHERE "deviceId"=$1 ORDER BY "completedAt" DESC,"id" DESC LIMIT 50))`,
          [id],
        );
      });
      return {
        collected: !!selected,
        checkedAt: completedAt.toISOString(),
        measurementCount: measurements.length,
        errorCode: selected ? null : "MONITOR_CONNECTION_FAILED",
      };
    } finally {
      this.running.delete(id);
      await this.db
        .createQueryBuilder()
        .update(DeviceMonitoring)
        .set({ leaseToken: null, leaseExpiresAt: null })
        .where('"deviceId"=:id AND "leaseToken"=:token', { id, token })
        .execute();
    }
  }
  async report(user: AppUser, id: string, query: MonitoringQueryDto) {
    const device = await this.devices.get(user, id),
      config = await this.db.getRepository(DeviceMonitoring).findOneBy({ deviceId: id });
    let valid = false;
    if (config?.latest && config.latest.companyId === device.companyId) {
      const actor = await this.db.getRepository(AppUser).findOneBy({ id: config.actorId });
      if (actor?.isActive)
        try {
          this.devices.managementScope(actor);
          if ((actor.workspaceOwnerId ?? actor.id) === device.workspaceOwnerId)
            valid = (await this.sources(this.db.manager, actor, device)).some(
              (s) => s.binding === config.latest?.binding,
            );
        } catch {
          /* No access to former owner's credentials. */
        }
    }
    const range = query.range ?? "24h",
      seconds = { "1h": 3600, "24h": 86400, "7d": 604800, "30d": 2592000 }[range];
    const rows: MetricRow[] = valid
      ? await this.db.query(
          `SELECT "metricKey","label","unit","kind","counterEpoch","bucketAt","firstAt","lastAt","firstValue","lastValue","sumValue","sampleCount" FROM "device_metric_buckets" WHERE "deviceId"=$1 AND "companyKey"=$2 AND "generation"=$3 AND "bucketAt">=$4 ORDER BY "lastAt"`,
          [id, device.companyId ?? "", config!.generation, new Date(Date.now() - seconds * 1000)],
        )
      : [];
    const history = await this.db.query(
      `SELECT "id","status","source","startedAt","completedAt","errorCode","measurementCount","warnings" FROM "device_monitor_runs" WHERE "deviceId"=$1 AND "companyId" IS NOT DISTINCT FROM $2 ORDER BY "completedAt" DESC,"id" DESC LIMIT 50`,
      [id, device.companyId],
    );
    const latest =
      valid && config?.latest
        ? {
            measurements: config.latest.measurements,
            warnings: config.latest.warnings,
            source: config.latest.source,
            collectedAt: config.latest.collectedAt,
          }
        : null;
    return {
      config: config
        ? {
            enabled: config.enabled,
            intervalSeconds: config.intervalSeconds,
            revision: config.revision,
            nextRunAt: config.nextRunAt,
            lastAttemptAt: config.lastAttemptAt,
            lastSuccessAt: config.lastSuccessAt,
            lastErrorCode: config.lastErrorCode,
            running: !!config.leaseExpiresAt && config.leaseExpiresAt > new Date(),
          }
        : null,
      latest,
      stale:
        !latest ||
        !!config?.lastErrorCode ||
        Date.now() - Date.parse(latest.collectedAt) > (config?.intervalSeconds ?? 300) * 2000,
      series: metricSeries(rows),
      history,
      range,
    };
  }
  async tick() {
    const due: { deviceId: string; actorId: string }[] = await this.db.query(
      `SELECT "deviceId","actorId" FROM "device_monitoring" WHERE "enabled"=true AND "nextRunAt"<=now() AND ("leaseExpiresAt" IS NULL OR "leaseExpiresAt"<now()) ORDER BY "nextRunAt" LIMIT 2`,
    );
    await Promise.allSettled(
      due.map(async (row) => {
        const actor = await this.db.getRepository(AppUser).findOneBy({ id: row.actorId });
        if (!actor) return;
        try {
          await this.collect(actor, row.deviceId, true);
        } catch (error) {
          if (!(
            error instanceof ForbiddenException ||
            error instanceof NotFoundException ||
            error instanceof BadRequestException
          ))
            return;
          await this.db.query(
            `UPDATE "device_monitoring" SET "enabled"=false,"nextRunAt"=NULL,"lastErrorCode"='MONITOR_CONFIGURATION_INVALID',"revision"=$3 WHERE "deviceId"=$1 AND "actorId"=$2 AND ("leaseExpiresAt" IS NULL OR "leaseExpiresAt"<now())`,
            [row.deviceId, row.actorId, randomUUID()],
          );
        }
      }),
    );
  }
}
