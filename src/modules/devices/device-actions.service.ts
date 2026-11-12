import { isFortiVdomAction, fortiVdomPrecheck, fortiVdomMessage } from "./fortigate-vdom";
import {
  isFortiClusterAction,
  isFortiClusterAuto,
  parseFortiSdwan,
  fortiClusterReadCommands,
  fortiClusterReadMetadata,
  fortiClusterPrecheck,
  fortiClusterMessage,
} from "./fortigate-cluster";
import { DeviceSecretsService } from "./device-secrets.service";
import {
  isFortiAdminAction,
  fortiAdminMessage,
  fortiAdminPasswordLine,
  fortiAdminPasswordPlaceholder,
} from "./fortigate-admin";
import {
  BadRequestException,
  BadGatewayException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import { createHmac, randomUUID } from "node:crypto";
import { DataSource, EntityManager } from "typeorm";
import { AppUser } from "../users/user.entity";
import { Device } from "./device.entity";
import { DevicesService } from "./devices.service";
import { sshVaultKey } from "./ssh-credential-vault";
import { runFortiSession } from "./fortigate-session";
import { fortiIdentity, isFortiConfigComplete, parseFortiBlocks } from "./fortigate-inventory";
import {
  compileFortiChange,
  assertFortiChange,
  fortiResource,
  fortiActionMatches,
  isFortiAutomaticCreate,
  fortiActionTarget,
  fortiActionBefore,
  fortiActionContexts,
} from "./fortigate-change";
import { type FortiPreparedInput, type FortiDependencyTables } from "./fortigate-policy";
import {
  parseFortiSystemConfig,
  isFortiNetworkAction,
  fortiNetworkMessage,
} from "./fortigate-network";
import type { ExecuteFortiActionDto } from "./fortigate-actions.dto";
const digest = (value: unknown) =>
  createHmac("sha256", sshVaultKey()).update(JSON.stringify(value)).digest("hex");
@Injectable()
export class DeviceActionsService {
  constructor(
    private readonly db: DataSource,
    private readonly devices: DevicesService,
    private readonly actionSecrets: DeviceSecretsService,
  ) {}
  private async target(manager: EntityManager, user: AppUser, id: string, lock = false) {
    const actor = await manager.findOne(AppUser, {
      where: { id: user.id },
      ...(lock ? { lock: { mode: "pessimistic_read" as const } } : {}),
    });
    if (
      !actor?.isActive ||
      this.devices.managementScope(actor) !== (user.workspaceOwnerId ?? user.id)
    )
      throw new ForbiddenException("دسترسی اجرای عملیات تغییر کرده است.");
    const device = await manager.findOne(Device, {
      where: { id, workspaceOwnerId: this.devices.managementScope(actor) },
      ...(lock ? { lock: { mode: "pessimistic_write" as const } } : {}),
    });
    if (!device) throw new NotFoundException("تجهیز فعال پیدا نشد.");
    if (device.type !== "fortigate" || device.protocol !== "ssh" || device.accessRoute !== "direct")
      throw new BadRequestException("این عملیات به اتصال SSH مستقیم FortiGate نیاز دارد.");
    const snapshot = await this.devices.savedSshCredentialSnapshot(actor, device, manager, lock);
    return {
      actor,
      device,
      ...snapshot,
      binding: digest([
        device.id,
        device.workspaceOwnerId,
        device.companyId,
        device.host,
        device.managementPort,
        device.type,
        device.protocol,
        device.accessRoute,
        device.updatedAt,
        actor.updatedAt,
        snapshot.revision,
      ]),
    };
  }
  private scope(vdom?: string) {
    return vdom ? ["config vdom", `edit "${vdom}"`] : [];
  }
  private async read(
    target: Awaited<ReturnType<DeviceActionsService["target"]>>,
    input: FortiPreparedInput,
  ) {
    try {
      const resource = fortiResource(input.action);
      const [identity] = await runFortiSession(target.device, target.credentials, [
        "get system status",
      ]);
      if (!fortiIdentity(identity).supported)
        throw new BadRequestException("هویت FortiOS تأیید نشد.");
      const multipleVdoms = /Virtual domain configuration:\s*(?:enable|multiple)/i.test(identity);
      const disabledVdoms = /Virtual domain configuration:\s*disable/i.test(identity);
      const currentVdom = identity.match(/^Current virtual domain:\s*(.+)$/im)?.[1]?.trim();
      const version = fortiIdentity(identity).version ?? "unknown";
      const metadata: FortiDependencyTables = {
        __fortios: [
          {
            name: "version",
            settings: {
              version: [version],
              vdomMode: [multipleVdoms ? "enabled" : disabledVdoms ? "disabled" : "unknown"],
            },
          },
        ],
      };
      if (isFortiVdomAction(input.action) && !multipleVdoms)
        throw new BadRequestException(
          "مدیریت VDOM به حالت چندـVDOM موجود نیاز دارد؛ این عملیات حالت عمومی دستگاه را تغییر نمی‌دهد.",
        );
      const extraReads = fortiClusterReadCommands(input.action);
      const contexts = fortiActionContexts(input.action, metadata),
        readCommands = contexts.map((context) => `show full-configuration ${context}`);

      let scope: string[] = [];
      if (resource.global) {
        if (multipleVdoms) scope = ["config global"];
      } else {
        if (multipleVdoms && !input.vdom) throw new BadRequestException("VDOM را مشخص کنید.");
        if (disabledVdoms && input.vdom && input.vdom !== "root")
          throw new BadRequestException("این تجهیز در حالت بدون VDOM است؛ root را انتخاب کنید.");
        if (input.vdom && (multipleVdoms || (input.vdom !== currentVdom && !disabledVdoms))) {
          if (input.vdom !== currentVdom) {
            const [catalog] = await runFortiSession(target.device, target.credentials, [
              "show system vdom",
            ]);
            if (
              !isFortiConfigComplete(catalog, "config system vdom") ||
              !parseFortiBlocks(catalog).some((row) => row.name === input.vdom)
            )
              throw new BadRequestException(
                "VDOM موجود انتخاب کنید؛ پیش‌نمایش VDOM جدید ایجاد نمی‌کند.",
              );
          }
          scope = this.scope(input.vdom);
        }
      }
      const results = await runFortiSession(target.device, target.credentials, [
        ...scope,
        ...readCommands,
        ...extraReads,
      ]);
      const configs = results.slice(scope.length, scope.length + contexts.length);
      const tables = {
        ...this.parseConfigs(contexts, configs),
        ...metadata,
        ...fortiClusterReadMetadata(input.action, results.slice(scope.length + contexts.length)),
      };
      return {
        hash: digest([configs, version, multipleVdoms, disabledVdoms]),
        rows: tables[resource.context],
        dependencies: resource.dependency ? tables[resource.dependency] : [],
        tables,
        scope,
      };
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof ForbiddenException ||
        error instanceof NotFoundException
      )
        throw error;
      throw new BadGatewayException(
        "پیکربندی تجهیز خوانده نشد؛ اتصال و مجوز فرمان‌ها را بررسی کنید.",
      );
    }
  }

  private parseConfigs(contexts: string[], configs: string[]): FortiDependencyTables {
    return Object.fromEntries(
      contexts.map((context, offset) => {
        const config = configs[offset] ?? "";
        if (!isFortiConfigComplete(config, `config ${context}`))
          throw new BadRequestException("پیکربندی کامل هدف یا وابستگی‌ها دریافت نشد.");
        const rows =
          context === "system sdwan"
            ? parseFortiSdwan(config)
            : (parseFortiSystemConfig(context, config) ?? parseFortiBlocks(config, 4097));
        if (rows.length > 4096)
          throw new BadRequestException(
            "پیکربندی از سقف بررسی کنترل‌شده بزرگ‌تر است؛ عملیات ارسال نشد.",
          );
        return [context, rows];
      }),
    );
  }

  private async event(
    manager: EntityManager,
    target: Awaited<ReturnType<DeviceActionsService["target"]>>,
    planId: string,
    action: string,
  ) {
    await manager.query(
      `INSERT INTO device_action_events(id,"deviceId","companyId","planId","actorName",action) VALUES ($1,$2,$3,$4,$5,$6)`,
      [
        randomUUID(),
        target.device.id,
        target.device.companyId,
        planId,
        target.actor.displayName,
        action,
      ],
    );
    await manager.query(
      `DELETE FROM device_action_events WHERE "planId"=$1 AND ("occurredAt"<now()-interval '30 days' OR id NOT IN (SELECT id FROM device_action_events WHERE "planId"=$1 ORDER BY "occurredAt" DESC,id DESC LIMIT 50))`,
      [planId],
    );
  }
  private async invalidate(manager: EntityManager, id: string) {
    await manager.query(`UPDATE devices SET verification=NULL WHERE id=$1`, [id]);
    await manager.query(
      `UPDATE device_capability_cache SET binding=NULL,"expiresAt"=NULL,"leaseToken"=NULL,"leaseExpiresAt"=NULL WHERE "deviceId"=$1`,
      [id],
    );
    await manager.query(
      `UPDATE device_monitoring SET enabled=false,"nextRunAt"=NULL,latest=NULL,generation=NULL,"counterEpoch"=NULL,"leaseToken"=NULL,"leaseExpiresAt"=NULL,revision=$2,"lastErrorCode"='MONITOR_CONFIGURATION_INVALID' WHERE "deviceId"=$1`,
      [id, randomUUID()],
    );
  }
  private async actionSecret(
    user: AppUser,
    input: FortiPreparedInput,
    manager = this.db.manager,
    lock = false,
  ) {
    if (input.action !== "admin.create") return undefined;
    if (!input.adminSecretId) throw new BadRequestException("راز گذرواژه را انتخاب کنید.");
    const secret = await this.actionSecrets.snapshot(
      user,
      input.adminSecretId,
      "admin_password",
      manager,
      lock,
    );
    const fingerprint = digest([input.adminSecretId, secret.revision]);
    if (input.secretFingerprint && input.secretFingerprint !== fingerprint)
      throw new ConflictException("راز از زمان پیش‌نمایش تغییر کرده است؛ پیش‌نمایش تازه بگیرید.");
    return { fingerprint, command: fortiAdminPasswordLine(secret.value) };
  }
  async preview(user: AppUser, id: string, input: FortiPreparedInput) {
    const planId = randomUUID();
    input = {
      ...input,
      secretFingerprint: undefined,
      ...(fortiResource(input.action).global ? { vdom: undefined } : {}),
      ...(isFortiAutomaticCreate(input.action) ? { executionTag: planId } : {}),
    };
    compileFortiChange(input);
    const target = await this.target(this.db.manager, user, id);
    const secret = await this.actionSecret(target.actor, input);
    if (secret) input = { ...input, secretFingerprint: secret.fingerprint };
    const current = await this.read(target, input),
      row = current.rows.find((row) => row.name === input.name),
      compiled = compileFortiChange(input, row, current.tables);
    assertFortiChange(input, compiled, current.rows, current.dependencies, current.tables);
    const before =
      (input.action.startsWith("policy.") ||
        isFortiNetworkAction(input.action) ||
        isFortiAdminAction(input.action) ||
        isFortiClusterAction(input.action) ||
        isFortiVdomAction(input.action)) &&
      (!compiled.deleting || isFortiVdomAction(input.action))
        ? fortiActionBefore(current.rows, input, compiled.assignments, current.tables)
        : compiled.deleting
          ? {
              exists: "present",
              ...Object.fromEntries(
                Object.entries(row?.settings ?? {})
                  .filter(([key]) =>
                    [
                      "dst",
                      "gateway",
                      "device",
                      "type",
                      "extip",
                      "mappedip",
                      "extintf",
                      "extport",
                      "mappedport",
                      "portforward",
                      "startip",
                      "endip",
                      "subnet",
                      "fqdn",
                      "start-ip",
                      "end-ip",
                      "country",
                      "comment",
                      "comments",
                      "name",
                      "srcintf",
                      "dstintf",
                      "srcaddr",
                      "dstaddr",
                      "action",
                      "service",
                      "schedule",
                      "status",
                      "nat",
                      "logtraffic",
                      "description",
                      "member",
                      "interface",
                      "intrazone",
                      "protocol",
                      "accprofile",
                      "vdom",
                      "trusthost1",
                      "disallowed-login-methods",
                      "tcp-portrange",
                      "udp-portrange",
                      "day",
                      "start",
                      "end",
                    ].includes(key),
                  )
                  .map(([key, value]) => [key, value.join(" ")]),
              ),
            }
          : Object.fromEntries(
              Object.keys(compiled.assignments).map((key) => [
                key,
                row?.settings[key]?.join(" ") ?? null,
              ]),
            );
    const preview = {
      action: input.action,
      name: input.action.startsWith("ha.")
        ? "HA"
        : input.action.startsWith("management.")
          ? "مدیریت دسترسی"
          : input.action === "dns.update"
            ? "DNS"
            : input.action === "ntp.update"
              ? "NTP"
              : input.action === "route.create"
                ? (input.destinationCidr ?? input.name)
                : input.action === "snat.create"
                  ? `SNAT ${input.srcInterface} → ${input.dstInterface}`
                  : input.name,
      vdom: fortiResource(input.action).global ? "global" : (input.vdom ?? null),
      before,
      after: compiled.assignments,
      commands: [...current.scope, ...compiled.commands],
      checks: isFortiVdomAction(input.action)
        ? fortiVdomPrecheck(input, current.tables)
        : fortiClusterPrecheck(input.action, current.tables),
      message: isFortiVdomAction(input.action)
        ? fortiVdomMessage(input)
        : isFortiClusterAction(input.action)
          ? fortiClusterMessage(input, current.tables)
          : isFortiAdminAction(input.action)
            ? fortiAdminMessage(input)
            : isFortiNetworkAction(input.action)
              ? fortiNetworkMessage(input, current.tables)
              : "تغییر تنظیمات می‌تواند بر شبکه و سیاست‌های وابسته اثر بگذارد. نتیجه فقط پس از خواندن دوباره تأیید می‌شود.",
    };
    await this.db.transaction(async (manager) => {
      const fresh = await this.target(manager, user, id, true);
      if (fresh.binding !== target.binding)
        throw new ConflictException("تجهیز یا اعتبارنامه هنگام پیش‌نمایش تغییر کرد.");
      await this.actionSecret(fresh.actor, input, manager, true);
      await manager.query(
        `INSERT INTO device_action_plans(id,"deviceId","companyId","requestedBy",action,input,preview,binding,"configHash","expiresAt") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now()+interval '5 minutes')`,
        [
          planId,
          id,
          target.device.companyId,
          user.id,
          input.action,
          input,
          preview,
          target.binding,
          current.hash,
        ],
      );
      await this.event(manager, fresh, planId, "preview");
      await manager.query(
        `DELETE FROM device_action_plans WHERE "deviceId"=$1 AND status<>'running' AND ("createdAt"<now()-interval '30 days' OR id NOT IN (SELECT id FROM device_action_plans WHERE "deviceId"=$1 ORDER BY "createdAt" DESC,id DESC LIMIT 50))`,
        [id],
      );
    });
    return { id: planId, ...preview, expiresAt: new Date(Date.now() + 300000).toISOString() };
  }
  async list(user: AppUser, id: string) {
    const device = await this.devices.get(user, id);
    await this.db.query(
      `UPDATE device_action_plans SET status='verification_pending',"errorCode"='ACTION_INTERRUPTED' WHERE "deviceId"=$1 AND status='running' AND "startedAt"<now()-interval '2 minutes'`,
      [id],
    );
    return {
      companyId: device.companyId,
      items: await this.db.query(
        `SELECT id,action,status,"connectorInvoked","errorCode","createdAt","completedAt",preview->>'name' AS "targetName",preview->>'resultTargetId' AS "targetId",preview->>'vdom' AS vdom,(SELECT "displayName" FROM app_users WHERE app_users.id="requestedBy") AS "actorName",("requestedBy"=$3 AND status='verification_pending' AND "connectorInvoked"=true) AS "canVerify" FROM device_action_plans WHERE "deviceId"=$1 AND "companyId" IS NOT DISTINCT FROM $2 AND "createdAt">now()-interval '30 days' ORDER BY "createdAt" DESC,id DESC LIMIT 50`,
        [id, device.companyId, user.id],
      ),
    };
  }
  async verify(user: AppUser, id: string, planId: string) {
    try {
      return await this.db.transaction(async (manager) => {
        const target = await this.target(manager, user, id, true),
          [plan] = await manager.query(
            `SELECT * FROM device_action_plans WHERE id=$1 AND "deviceId"=$2 AND "requestedBy"=$3 FOR UPDATE`,
            [planId, id, user.id],
          );
        if (!plan || plan.companyId !== target.device.companyId)
          throw new NotFoundException("عملیات پیدا نشد.");
        if (
          plan.status !== "verification_pending" ||
          !plan.connectorInvoked ||
          plan.binding !== target.binding
        )
          throw new ConflictException("این نتیجه برای تأیید خواندنی با اتصال فعلی معتبر نیست.");
        await this.actionSecret(target.actor, plan.input, manager, true);
        const current = await this.read(target, plan.input),
          verified = fortiActionMatches(
            current.rows,
            plan.input,
            plan.preview.after,
            current.tables,
          );
        if (verified)
          await manager.query(
            `UPDATE device_action_plans SET status='succeeded',"completedAt"=now(),"errorCode"=NULL WHERE id=$1`,
            [planId],
          );
        const targetId =
          verified &&
          !fortiResource(plan.input.action).global &&
          (plan.input.action.startsWith("policy.") ||
            isFortiNetworkAction(plan.input.action) ||
            isFortiClusterAuto(plan.input.action))
            ? fortiActionTarget(current.rows, plan.input, plan.preview.after)?.name
            : undefined;
        if (targetId)
          await manager.query(
            `UPDATE device_action_plans SET preview=jsonb_set(preview,'{resultTargetId}',to_jsonb($2::text)) WHERE id=$1`,
            [planId, targetId],
          );
        await this.event(manager, target, planId, verified ? "verified" : "verification_pending");
        return {
          id: planId,
          status: verified ? "succeeded" : "verification_pending",
          connectorInvoked: true,
          verified,
          targetId,
        };
      });
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof ConflictException ||
        error instanceof ForbiddenException ||
        error instanceof NotFoundException
      )
        throw error;
      throw new BadGatewayException("خواندن نتیجه ممکن نشد؛ اتصال را بررسی و دوباره تلاش کنید.");
    }
  }
  async execute(user: AppUser, id: string, planId: string, input: ExecuteFortiActionDto) {
    if (input.intent !== "execute" || input.confirmed !== true)
      throw new BadRequestException("اجرای عملیات به تأیید نیاز دارد.");
    await this.db.transaction(async (manager) => {
      const target = await this.target(manager, user, id, true),
        [plan] = await manager.query(
          `SELECT * FROM device_action_plans WHERE id=$1 AND "deviceId"=$2 AND "requestedBy"=$3 FOR UPDATE`,
          [planId, id, user.id],
        );
      if (!plan || plan.companyId !== target.device.companyId)
        throw new NotFoundException("پیش‌نمایش پیدا نشد.");
      if (
        plan.status !== "preview" ||
        new Date(plan.expiresAt) < new Date() ||
        plan.binding !== target.binding
      )
        throw new ConflictException("پیش‌نمایش منقضی یا قبلاً مصرف شده است.");
      await this.actionSecret(target.actor, plan.input, manager, true);
      const current = await this.read(target, plan.input);
      if (current.hash !== plan.configHash)
        throw new ConflictException(
          "پیکربندی از زمان پیش‌نمایش تغییر کرده است؛ پیش‌نمایش تازه بگیرید.",
        );
      await manager.query(
        `UPDATE device_action_plans SET status='running',"startedAt"=now() WHERE id=$1`,
        [planId],
      );
      await this.event(manager, target, planId, "confirmed");
    });
    let invoked = false;
    try {
      return await this.db.transaction(async (manager) => {
        const target = await this.target(manager, user, id, true),
          [plan] = await manager.query(`SELECT * FROM device_action_plans WHERE id=$1 FOR UPDATE`, [
            planId,
          ]);
        if (plan.status !== "running" || target.binding !== plan.binding)
          throw new ConflictException("تنظیم اتصال تغییر کرده است.");
        const actionSecret = await this.actionSecret(target.actor, plan.input, manager, true);
        const current = await this.read(target, plan.input);
        if (current.hash !== plan.configHash)
          throw new ConflictException("پیکربندی تغییر کرد؛ فرمان ارسال نشد.");
        const compiled = compileFortiChange(
          plan.input,
          current.rows.find((row) => row.name === plan.input.name),
          current.tables,
        );
        assertFortiChange(plan.input, compiled, current.rows, current.dependencies, current.tables);
        const contexts = fortiActionContexts(plan.input.action, current.tables),
          extraReads = fortiClusterReadCommands(plan.input.action);
        const commands = compiled.commands.map((command) => {
          if (command !== fortiAdminPasswordPlaceholder) return command;
          if (!actionSecret) throw new BadRequestException("راز اجرای ساخت حساب موجود نیست.");
          return actionSecret.command;
        });
        invoked = true;
        const vdomAction = isFortiVdomAction(plan.input.action);
        const results = await runFortiSession(
          target.device,
          target.credentials,
          [
            ...current.scope,
            ...commands,
            ...(vdomAction ? [] : contexts.map((context) => `show full-configuration ${context}`)),
            ...(vdomAction ? [] : extraReads),
          ],
          plan.input.action === "vdom.create"
            ? { confirmVdomCreate: { name: plan.input.name } }
            : {},
        );
        let tables: FortiDependencyTables;
        try {
          if (vdomAction) tables = (await this.read(target, plan.input)).tables;
          else {
            const readback = results.slice(-(contexts.length + extraReads.length));
            tables = {
              ...this.parseConfigs(contexts, readback.slice(0, contexts.length)),
              ...fortiClusterReadMetadata(plan.input.action, readback.slice(contexts.length)),
            };
          }
        } catch {
          throw Object.assign(new Error("FORTI_READBACK_INCOMPLETE"), {
            code: "FORTI_READBACK_INCOMPLETE",
          });
        }
        const verified = fortiActionMatches(
            tables[compiled.context],
            plan.input,
            plan.preview.after,
            tables,
          ),
          status = verified ? "succeeded" : "verification_failed";
        const targetId =
          verified &&
          !fortiResource(plan.input.action).global &&
          (plan.input.action.startsWith("policy.") ||
            isFortiNetworkAction(plan.input.action) ||
            isFortiClusterAuto(plan.input.action)) &&
          !compiled.deleting
            ? fortiActionTarget(tables[compiled.context], plan.input, plan.preview.after)?.name
            : undefined;

        await manager.query(
          `UPDATE device_action_plans SET status=$2,"connectorInvoked"=true,"completedAt"=now(),"errorCode"=$3 WHERE id=$1`,
          [planId, status, verified ? null : "ACTION_VERIFICATION_MISMATCH"],
        );
        await this.event(manager, target, planId, status);
        await this.invalidate(manager, id);
        if (targetId)
          await manager.query(
            `UPDATE device_action_plans SET preview=jsonb_set(preview,'{resultTargetId}',to_jsonb($2::text)) WHERE id=$1`,
            [planId, targetId],
          );
        return { id: planId, status, connectorInvoked: true, verified, targetId };
      });
    } catch (error) {
      const code = (error as { code?: string }).code,
        status =
          invoked &&
          [
            "FORTI_SESSION_TIMEOUT",
            "FORTI_SESSION_CLOSED",
            "FORTI_SSH_FAILED",
            "FORTI_READBACK_INCOMPLETE",
            "FORTI_CONFIRMATION_REQUIRED",
          ].includes(code ?? "")
            ? "verification_pending"
            : "failed";
      await this.db.query(
        `UPDATE device_action_plans SET status=$2,"connectorInvoked"=$3,"errorCode"=$4,"completedAt"=now() WHERE id=$1 AND status='running'`,
        [
          planId,
          status,
          invoked,
          invoked ? "ACTION_EXECUTION_UNCONFIRMED" : "ACTION_CONFIGURATION_CHANGED",
        ],
      );
      if (invoked)
        await this.db.transaction(async (manager) => {
          const [plan] = await manager.query(
            `SELECT "companyId" FROM device_action_plans WHERE id=$1`,
            [planId],
          );
          const current = await manager.findOne(Device, {
            where: { id },
            lock: { mode: "pessimistic_write" },
          });
          if (current && current.companyId === plan?.companyId) await this.invalidate(manager, id);
        });
      await this.db.query(
        `INSERT INTO device_action_events(id,"deviceId","companyId","planId","actorName",action) SELECT $1,"deviceId","companyId",id,$3,$4 FROM device_action_plans WHERE id=$2`,
        [randomUUID(), planId, user.displayName, status],
      );
      return { id: planId, status, connectorInvoked: invoked, verified: false };
    }
  }
}
