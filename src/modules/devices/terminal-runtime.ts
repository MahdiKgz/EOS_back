import { HttpException } from "@nestjs/common";
import { randomUUID } from "node:crypto";
import { Client, type ClientChannel, type ConnectConfig } from "ssh2";

export class TerminalError extends HttpException {
  constructor(
    public readonly code: string,
    statusCode = 409,
  ) {
    super({ code, message: terminalMessage(code) }, statusCode);
  }
}
export function terminalMessage(code: string) {
  const messages: Record<string, string> = {
    SSH_AUTH_FAILED: "اعتبارنامهٔ SSH پذیرفته نشد.",
    SSH_HOST_KEY_MISMATCH: "هویت SSH تجهیز با کلید ذخیره‌شده مطابقت ندارد.",
    SSH_CONNECTION_REFUSED: "تجهیز اتصال SSH را نپذیرفت.",
    SSH_HANDSHAKE_TIMEOUT: "مهلت اتصال SSH تمام شد.",
    TERMINAL_NOT_FOUND: "نشست ترمینال پیدا نشد.",
    TERMINAL_SESSION_LIMIT: "تعداد نشست‌های هم‌زمان به سقف مجاز رسیده است.",
    TERMINAL_PREVIEW_EXPIRED:
      "پیش‌نمایش منقضی شده یا تنظیمات اتصال تغییر کرده است. دوباره بررسی کنید.",
    TERMINAL_CONFIGURATION_CHANGED: "دسترسی یا تنظیمات اتصال تغییر کرده و نشست بسته شد.",
    TERMINAL_INPUT_SEQUENCE: "ترتیب ورودی معتبر نیست؛ اتصال را دوباره برقرار کنید.",
    TERMINAL_AUDIT_UNAVAILABLE: "ثبت سابقهٔ نشست ممکن نشد. دوباره تلاش کنید.",
  };
  return messages[code] ?? "نشست SSH در دسترس نیست. اتصال و مجوزهای تجهیز را بررسی کنید.";
}
export type TerminalOwner = {
  userId: string;
  sessionHash: string;
  ownerId: string;
  companyId?: string | null;
};
export type TerminalIdentity = TerminalOwner & {
  deviceId: string;
  revision: string;
  fingerprint: string;
};
type Chunk = { sequence: number; bytes: Buffer };
type Session = TerminalIdentity & {
  id: string;
  client: Client;
  channel?: ClientChannel;
  state: "connecting" | "connected" | "closed";
  reason: string | null;
  openedAt: number;
  touchedAt: number;
  inputAt: number;
  inputSequence: number;
  chunks: Chunk[];
  sequence: number;
  retainedBytes: number;
  outputBytes: number;
  inputBytes: number;
  windowAt: number;
  windowBytes: number;
  done: boolean;
};
export const TERMINAL_LIMITS = {
  global: 8,
  perUser: 2,
  retentionBytes: 256 * 1024,
  outputBytes: 32 * 1024 * 1024,
  inputBytes: 32 * 1024,
  idleMs: 10 * 60_000,
  leaseMs: 120_000,
  lifetimeMs: 2 * 60 * 60_000,
} as const;
export function terminalSize(cols: unknown, rows: unknown) {
  if (
    !Number.isInteger(cols) ||
    !Number.isInteger(rows) ||
    Number(cols) < 20 ||
    Number(cols) > 240 ||
    Number(rows) < 5 ||
    Number(rows) > 80
  )
    throw new TerminalError("TERMINAL_SIZE_INVALID", 400);
  return { cols: Number(cols), rows: Number(rows) };
}
export function terminalSshError(error: unknown) {
  const e = error as { code?: string; level?: string; message?: string };
  return e?.level === "client-authentication"
    ? "SSH_AUTH_FAILED"
    : /host.*verification|host denied/i.test(e?.message ?? "")
      ? "SSH_HOST_KEY_MISMATCH"
      : e?.code === "ECONNREFUSED"
        ? "SSH_CONNECTION_REFUSED"
        : /timed out|timeout/i.test(e?.message ?? "") || e?.code === "ETIMEDOUT"
          ? "SSH_HANDSHAKE_TIMEOUT"
          : "SSH_CONNECTION_FAILED";
}

/** Dedicated human-operated PTYs. Never share a collector connection or persist I/O. */
export class TerminalRuntime {
  private sessions = new Map<string, Session>();
  private audits = new Set<Promise<unknown>>();
  private timer: NodeJS.Timeout;
  constructor(
    private readonly closed: (
      session: TerminalIdentity & {
        id: string;
        reason: string;
        inputBytes: number;
        outputBytes: number;
        durationMs: number;
      },
    ) => Promise<void>,
  ) {
    this.timer = setInterval(() => this.sweep(), 10_000);
    this.timer.unref();
  }
  private finish(s: Session, reason: string) {
    if (s.done) return;
    s.done = true;
    s.state = "closed";
    s.reason = reason;
    s.touchedAt = Date.now();
    s.channel?.destroy();
    s.client.destroy();
    const event = Promise.resolve()
      .then(() =>
        this.closed({
          userId: s.userId,
          sessionHash: s.sessionHash,
          ownerId: s.ownerId,
          companyId: s.companyId,
          deviceId: s.deviceId,
          revision: s.revision,
          fingerprint: s.fingerprint,
          id: s.id,
          reason,
          inputBytes: s.inputBytes,
          outputBytes: s.outputBytes,
          durationMs: Date.now() - s.openedAt,
        }),
      )
      .catch(() => {});
    this.audits.add(event);
    void event.finally(() => this.audits.delete(event));
  }
  sweep(now = Date.now()) {
    for (const [id, s] of this.sessions) {
      if (s.done) {
        if (now - s.touchedAt > 30_000) this.sessions.delete(id);
        continue;
      }
      if (now - s.touchedAt > TERMINAL_LIMITS.leaseMs) this.finish(s, "browser_disconnected");
      else if (now - s.inputAt > TERMINAL_LIMITS.idleMs) this.finish(s, "idle_timeout");
      else if (now - s.openedAt > TERMINAL_LIMITS.lifetimeMs) this.finish(s, "session_expired");
    }
  }
  active(userId?: string) {
    return [...this.sessions.values()].filter((s) => !s.done && (!userId || s.userId === userId))
      .length;
  }
  async revalidate(check: (identity: TerminalIdentity) => Promise<boolean>) {
    await Promise.all(
      [...this.sessions.values()]
        .filter((s) => !s.done)
        .map(async (s) => {
          try {
            if (!(await check(s))) this.finish(s, "authorization_changed");
          } catch {
            this.finish(s, "authorization_changed");
          }
        }),
    );
  }
  async open(
    identity: TerminalIdentity,
    config: ConnectConfig,
    size: { cols: number; rows: number },
    admitted: (id: string) => Promise<void>,
  ) {
    if (
      this.active() >= TERMINAL_LIMITS.global ||
      this.active(identity.userId) >= TERMINAL_LIMITS.perUser
    )
      throw new TerminalError("TERMINAL_SESSION_LIMIT", 429);
    if (this.sessions.size >= 64) {
      const oldest = [...this.sessions.values()].find((s) => s.done);
      if (oldest) this.sessions.delete(oldest.id);
    }
    const client = new Client(),
      now = Date.now();
    const s: Session = {
      ...identity,
      id: randomUUID(),
      client,
      state: "connecting",
      reason: null,
      openedAt: now,
      touchedAt: now,
      inputAt: now,
      inputSequence: 0,
      chunks: [],
      sequence: 0,
      retainedBytes: 0,
      inputBytes: 0,
      outputBytes: 0,
      windowAt: now,
      windowBytes: 0,
      done: false,
    };
    this.sessions.set(s.id, s);
    // Audit must succeed before any authenticated SSH connection is attempted.
    try {
      await admitted(s.id);
    } catch {
      this.sessions.delete(s.id);
      client.destroy();
      throw new TerminalError("TERMINAL_AUDIT_UNAVAILABLE", 503);
    }
    if (s.done) throw new TerminalError("TERMINAL_NOT_CONNECTED");
    return new Promise<{ id: string; state: string }>((resolve, reject) => {
      let settled = false;
      const fail = (code: string) => {
        this.finish(s, code);
        if (!settled) {
          settled = true;
          clearTimeout(deadline);
          reject(new TerminalError(code, 502));
        }
      };
      const deadline = setTimeout(() => fail("SSH_HANDSHAKE_TIMEOUT"), 20_000);
      deadline.unref();
      client.on("error", (error) => fail(terminalSshError(error)));
      client.once("close", () => {
        if (!s.done) fail("SSH_SESSION_CLOSED");
      });
      client.once("ready", () => {
        if (s.done) return;
        client.shell(
          { term: "xterm-256color", cols: size.cols, rows: size.rows, width: 0, height: 0 },
          (error, channel) => {
            if (error) return fail("SSH_SHELL_UNAVAILABLE");
            if (s.done) {
              channel.destroy();
              return;
            }
            s.channel = channel;
            s.state = "connected";
            const append = (chunk: Buffer) => {
              if (s.done) return;
              s.outputBytes += chunk.length;
              if (s.outputBytes > TERMINAL_LIMITS.outputBytes) return fail("TERMINAL_OUTPUT_LIMIT");
              for (let offset = 0; offset < chunk.length; offset += 16 * 1024) {
                const bytes = Buffer.from(chunk.subarray(offset, offset + 16 * 1024));
                s.chunks.push({ sequence: ++s.sequence, bytes });
                s.retainedBytes += bytes.length;
              }
              while (s.retainedBytes > TERMINAL_LIMITS.retentionBytes && s.chunks.length > 1)
                s.retainedBytes -= s.chunks.shift()!.bytes.length;
            };
            channel.on("data", append);
            channel.stderr.on("data", append);
            channel.on("error", () => fail("SSH_CHANNEL_FAILED"));
            channel.once("close", () => this.finish(s, "remote_closed"));
            settled = true;
            clearTimeout(deadline);
            resolve({ id: s.id, state: s.state });
          },
        );
      });
      if (config.tryKeyboard && config.password)
        client.on("keyboard-interactive", (_name, _instructions, _lang, prompts, respond) =>
          respond(prompts.map(() => String(config.password))),
        );
      try {
        client.connect({ ...config, keepaliveInterval: 15_000, keepaliveCountMax: 3 });
      } catch {
        fail("SSH_CONNECTION_FAILED");
      }
    });
  }
  owned(id: string, owner: TerminalOwner) {
    const s = this.sessions.get(id);
    if (
      !s ||
      s.userId !== owner.userId ||
      s.sessionHash !== owner.sessionHash ||
      s.ownerId !== owner.ownerId ||
      s.companyId !== owner.companyId
    )
      throw new TerminalError("TERMINAL_NOT_FOUND", 404);
    return s;
  }
  read(id: string, owner: TerminalOwner, cursor: number) {
    const s = this.owned(id, owner);
    if (!Number.isSafeInteger(cursor) || cursor < 0 || cursor > s.sequence)
      throw new TerminalError("TERMINAL_CURSOR_INVALID", 400);
    s.touchedAt = Date.now();
    const floor = s.chunks[0]?.sequence ?? s.sequence + 1,
      chunks: Chunk[] = [];
    let bytes = 0;
    for (const chunk of s.chunks) {
      if (chunk.sequence <= cursor) continue;
      if (bytes + chunk.bytes.length > 64 * 1024) break;
      chunks.push(chunk);
      bytes += chunk.bytes.length;
    }
    const nextCursor = chunks.at(-1)?.sequence ?? s.sequence;
    return {
      id: s.id,
      state: s.state,
      reason: s.reason,
      truncated: cursor < floor - 1,
      cursor: nextCursor,
      hasMore: nextCursor < s.sequence,
      data: Buffer.concat(chunks.map((c) => c.bytes)).toString("base64"),
      openedAt: new Date(s.openedAt).toISOString(),
    };
  }
  input(id: string, owner: TerminalOwner, sequence: number, data: string) {
    const s = this.owned(id, owner);
    if (s.state !== "connected" || !s.channel) throw new TerminalError("TERMINAL_NOT_CONNECTED");
    if (!Number.isSafeInteger(sequence) || sequence !== s.inputSequence + 1)
      throw new TerminalError("TERMINAL_INPUT_SEQUENCE", 409);
    if (
      typeof data !== "string" ||
      !data.length ||
      Buffer.byteLength(data) > TERMINAL_LIMITS.inputBytes
    )
      throw new TerminalError("TERMINAL_INPUT_LIMIT", 400);
    const now = Date.now();
    if (now - s.windowAt > 60_000) {
      s.windowAt = now;
      s.windowBytes = 0;
    }
    s.windowBytes += Buffer.byteLength(data);
    if (s.windowBytes > 512 * 1024) {
      this.finish(s, "TERMINAL_INPUT_LIMIT");
      throw new TerminalError("TERMINAL_INPUT_LIMIT", 429);
    }
    if (s.channel.writableLength > 64 * 1024) {
      this.finish(s, "TERMINAL_INPUT_BACKPRESSURE");
      throw new TerminalError("TERMINAL_INPUT_BACKPRESSURE", 429);
    }
    s.inputSequence = sequence;
    s.touchedAt = now;
    s.inputAt = now;
    s.inputBytes += Buffer.byteLength(data);
    s.channel.write(data, "utf8");
    return { accepted: true, sequence };
  }
  resize(id: string, owner: TerminalOwner, cols: number, rows: number) {
    const s = this.owned(id, owner);
    const size = terminalSize(cols, rows);
    if (s.state !== "connected" || !s.channel) throw new TerminalError("TERMINAL_NOT_CONNECTED");
    s.channel.setWindow(size.rows, size.cols, 0, 0);
    return { resized: true };
  }
  close(id: string, owner: TerminalOwner, reason = "user_disconnected") {
    this.finish(this.owned(id, owner), reason);
    return { closed: true };
  }
  async shutdown() {
    clearInterval(this.timer);
    for (const s of this.sessions.values()) this.finish(s, "service_stopped");
    this.sessions.clear();
    await Promise.allSettled([...this.audits]);
  }
}
