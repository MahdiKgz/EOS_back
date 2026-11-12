import { legacyCiscoAlgorithms } from "./cisco-access-error";
import { BadRequestException, Injectable, OnModuleDestroy } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { createHash, randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { Repository, MoreThan } from "typeorm";
import type { ConnectConfig } from "ssh2";
import type { AuthenticatedSession } from "../auth/auth.service";
import { AuthSession } from "../auth/auth-session.entity";
import { Device } from "./device.entity";
import { DevicesService } from "./devices.service";
import {
  TerminalRuntime,
  TerminalError,
  terminalSize,
  type TerminalOwner,
  type TerminalIdentity,
} from "./terminal-runtime";

type Preview = { deviceId: string; revision: string; owner: TerminalOwner; expires: number };

@Injectable()
export class DeviceTerminalService implements OnModuleDestroy {
  private readonly previews = new Map<string, Preview>();
  private readonly opening = new Set<string>();
  readonly runtime: TerminalRuntime;
  private readonly timer: NodeJS.Timeout;
  private revalidating = false;
  constructor(
    private readonly devicesService: DevicesService,
    @InjectRepository(Device) private readonly devices: Repository<Device>,
  ) {
    this.runtime = new TerminalRuntime(async (s) => {
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          await this.audit(s, s.id, "closed", {
            reason: s.reason,
            inputBytes: s.inputBytes,
            outputBytes: s.outputBytes,
            durationMs: s.durationMs,
          });
          return;
        } catch {
          if (attempt < 2) await new Promise((resolve) => setTimeout(resolve, 150 * (attempt + 1)));
        }
      }
    });
    this.timer = setInterval(() => {
      if (this.revalidating) return;
      this.revalidating = true;
      void this.runtime
        .revalidate(async (identity) => {
          const auth = await this.authority(identity);
          if (!auth) return false;
          const t = await this.target(auth, identity.deviceId);
          return t.revision === identity.revision;
        })
        .finally(() => {
          this.revalidating = false;
        });
      for (const [id, p] of this.previews) if (p.expires <= Date.now()) this.previews.delete(id);
    }, 5000);
    this.timer.unref();
  }
  async onModuleDestroy() {
    clearInterval(this.timer);
    this.previews.clear();
    await this.runtime.shutdown();
  }
  private owner(auth: AuthenticatedSession): TerminalOwner {
    const workspace = this.devicesService.managementScope(auth.user);
    return { userId: auth.user.id, ownerId: workspace, sessionHash: auth.session.id };
  }
  private async authority(identity: TerminalOwner) {
    const session = await this.devices.manager.findOne(AuthSession, {
      where: { id: identity.sessionHash, userId: identity.userId, expiresAt: MoreThan(new Date()) },
      relations: { user: true },
    });
    if (!session?.user.isActive) return null;
    const auth = { user: session.user, session };
    const owner = this.owner(auth);
    return owner.ownerId === identity.ownerId ? auth : null;
  }
  private async target(auth: AuthenticatedSession, id: string) {
    const owner = this.owner(auth);
    const device = await this.devicesService.managedDevice(auth.user, id);
    if (device.protocol !== "ssh" || device.accessRoute !== "direct")
      throw new BadRequestException("ابتدا اتصال SSH مستقیم تجهیز را تنظیم کنید.");
    const snapshot = await this.devicesService.savedSshCredentialSnapshot(auth.user, device);
    const credentials = snapshot.credentials;
    const parts = credentials.hostKey.split(" ");
    if (parts.length !== 2) throw new BadRequestException("کلید هویت SSH ذخیره‌شده معتبر نیست.");
    const fingerprint =
      "SHA256:" +
      createHash("sha256")
        .update(Buffer.from(parts[1], "base64"))
        .digest("base64")
        .replace(/=+$/, "");
    const revision = createHash("sha256")
      .update(
        JSON.stringify([
          device.id,
          device.name,
          device.type,
          device.vendor,
          device.companyId,
          device.host,
          device.managementPort,
          device.protocol,
          device.accessRoute,
          device.credentialId,
          credentials,
          snapshot.revision,
        ]),
      )
      .digest("hex");
    return { owner, device, credentials, fingerprint, revision };
  }
  private async audit(
    s: TerminalIdentity,
    sessionId: string,
    action: string,
    details: {
      reason?: string;
      inputBytes?: number;
      outputBytes?: number;
      durationMs?: number;
    } = {},
  ) {
    // Deliberately no commands, output, credentials, JWT or fingerprint in audit.
    await this.devices.manager.query(
      `INSERT INTO "device_terminal_events" ("deviceId","sessionId","actorId","actorName","action","reason","inputBytes","outputBytes","durationMs")
      SELECT $1,$2,$3,COALESCE((SELECT "displayName" FROM "app_users" WHERE "id"=$3),'کاربر حذف‌شده'),$4,$5,$6,$7,$8`,
      [
        s.deviceId,
        sessionId,
        s.userId,
        action,
        details.reason ?? null,
        details.inputBytes ?? null,
        details.outputBytes ?? null,
        details.durationMs ?? null,
      ],
    );
  }
  async metadata(auth: AuthenticatedSession, id: string) {
    const owner = this.owner(auth);
    const device = await this.devicesService.managedDevice(auth.user, id);
    const events = await this.devices.manager.query(
      `SELECT "id"::text,"action","reason","actorName","inputBytes"::text,"outputBytes"::text,"durationMs"::text,"occurredAt" FROM "device_terminal_events" WHERE "deviceId"=$1 ORDER BY "occurredAt" DESC,"id" DESC LIMIT 20`,
      [device.id],
    );
    let username: string | null = null,
      fingerprint: string | null = null;
    if (device.protocol === "ssh") {
      try {
        const t = await this.target(auth, id);
        username = t.credentials.username;
        fingerprint = t.fingerprint;
      } catch {
        /* Metadata remains usable when a credential needs repair. */
      }
    }
    return {
      device: {
        id: device.id,
        name: device.name,
        host: device.host,
        port: device.managementPort,
        vendor: device.vendor,
      },
      supported: device.protocol === "ssh",
      credentialsConfigured: !!username,
      username,
      fingerprint,
      events,
      activeSessions: this.runtime.active(owner.userId),
    };
  }
  async preview(auth: AuthenticatedSession, id: string) {
    const t = await this.target(auth, id);
    for (const [key, p] of this.previews) if (p.expires <= Date.now()) this.previews.delete(key);
    if (
      this.previews.size >= 64 ||
      [...this.previews.values()].filter((p) => p.owner.userId === t.owner.userId).length >= 8
    )
      throw new TerminalError("TERMINAL_SESSION_LIMIT", 429);
    const previewId = randomUUID(),
      expires = Date.now() + 120000;
    this.previews.set(previewId, { deviceId: id, owner: t.owner, revision: t.revision, expires });
    return {
      previewId,
      expiresAt: new Date(expires).toISOString(),
      device: { id, name: t.device.name, host: t.device.host, port: t.device.managementPort },
      username: t.credentials.username,
      fingerprint: t.fingerprint,
    };
  }
  async open(
    auth: AuthenticatedSession,
    id: string,
    input: { previewId: string; intent: string; confirmed: boolean; cols: number; rows: number },
  ) {
    const owner = this.owner(auth),
      p = this.previews.get(input.previewId);
    if (
      !p ||
      p.deviceId !== id ||
      p.expires <= Date.now() ||
      JSON.stringify(p.owner) !== JSON.stringify(owner)
    )
      throw new TerminalError("TERMINAL_PREVIEW_EXPIRED");
    if (input.intent !== "execute" || input.confirmed !== true)
      throw new BadRequestException("اتصال به تأیید شما نیاز دارد.");
    const size = terminalSize(input.cols, input.rows);
    if (this.opening.size >= 8 || this.opening.has(owner.sessionHash))
      throw new TerminalError("TERMINAL_SESSION_LIMIT", 429);
    this.opening.add(owner.sessionHash);
    this.previews.delete(input.previewId);
    try {
      const t = await this.target(auth, id);
      if (t.revision !== p.revision) throw new TerminalError("TERMINAL_PREVIEW_EXPIRED");
      let address: string;
      try {
        address = isIP(t.device.host) ? t.device.host : (await lookup(t.device.host)).address;
      } catch {
        throw new TerminalError("SSH_DNS_FAILED", 502);
      }
      const config: ConnectConfig = {
        ...(t.device.type === "cisco" && t.credentials.cisco?.profile === "legacy_cisco"
          ? { algorithms: legacyCiscoAlgorithms }
          : {}),
        host: address,
        port: t.device.managementPort,
        username: t.credentials.username,
        password: t.credentials.password,
        privateKey: t.credentials.privateKey,
        readyTimeout: 15000,
        tryKeyboard: !!t.credentials.password,
        hostVerifier: (raw: Buffer) =>
          "SHA256:" + createHash("sha256").update(raw).digest("base64").replace(/=+$/, "") ===
          t.fingerprint,
      };
      const identity = { ...owner, deviceId: id, revision: t.revision, fingerprint: t.fingerprint };
      const result = await this.runtime.open(identity, config, size, (sessionId) =>
        this.audit(identity, sessionId, "requested"),
      );
      try {
        const current = await this.authority(owner);
        if (!current || (await this.target(current, id)).revision !== t.revision)
          throw new TerminalError("TERMINAL_CONFIGURATION_CHANGED");
        await this.audit(identity, result.id, "connected");
        return result;
      } catch {
        this.runtime.close(result.id, owner, "authorization_changed");
        throw new TerminalError("TERMINAL_CONFIGURATION_CHANGED");
      }
    } finally {
      this.opening.delete(owner.sessionHash);
    }
  }
  private async checked(auth: AuthenticatedSession, deviceId: string, sessionId: string) {
    const owner = this.owner(auth),
      s = this.runtime.owned(sessionId, owner);
    if (s.deviceId !== deviceId) throw new TerminalError("TERMINAL_NOT_FOUND", 404);
    if (s.state !== "closed") {
      try {
        if ((await this.target(auth, deviceId)).revision !== s.revision) throw new Error();
      } catch {
        this.runtime.close(sessionId, owner, "authorization_changed");
        throw new TerminalError("TERMINAL_CONFIGURATION_CHANGED");
      }
    }
    return owner;
  }
  async read(auth: AuthenticatedSession, id: string, sessionId: string, cursor: number) {
    return this.runtime.read(sessionId, await this.checked(auth, id, sessionId), cursor);
  }
  async input(
    auth: AuthenticatedSession,
    id: string,
    sessionId: string,
    sequence: number,
    data: string,
  ) {
    return this.runtime.input(sessionId, await this.checked(auth, id, sessionId), sequence, data);
  }
  async resize(
    auth: AuthenticatedSession,
    id: string,
    sessionId: string,
    cols: number,
    rows: number,
  ) {
    return this.runtime.resize(sessionId, await this.checked(auth, id, sessionId), cols, rows);
  }
  close(auth: AuthenticatedSession, id: string, sessionId: string) {
    const owner = this.owner(auth);
    if (this.runtime.owned(sessionId, owner).deviceId !== id)
      throw new TerminalError("TERMINAL_NOT_FOUND", 404);
    return this.runtime.close(sessionId, owner);
  }
}
