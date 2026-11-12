import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import { createCipheriv, createDecipheriv, createHmac, randomBytes, randomUUID } from "node:crypto";
import { DataSource, type EntityManager } from "typeorm";
import { AppUser } from "../users/user.entity";
import { DeviceActionSecret } from "./device-secret.entity";
import { sshVaultKey } from "./ssh-credential-vault";
import type { SaveDeviceSecretDto } from "./device-secrets.controller";
const context = (owner: string, id: string, purpose: string) =>
  Buffer.from(JSON.stringify(["eos-device-action-secret-v1", owner, id, purpose]));
const key = () => createHmac("sha256", sshVaultKey()).update("device-action-secrets-v1").digest();
@Injectable()
export class DeviceSecretsService {
  constructor(private readonly db: DataSource) {}
  private scope(user: AppUser) {
    if (user.allowedSections.length && !user.allowedSections.includes("assets"))
      throw new ForbiddenException("به دارایی‌ها دسترسی ندارید.");
  }
  async list(user: AppUser) {
    this.scope(user);
    return this.db.getRepository(DeviceActionSecret).find({
      where: { ownerId: user.id },
      select: { id: true, name: true, purpose: true, revision: true },
      order: { name: "ASC" },
    });
  }
  async save(user: AppUser, input: SaveDeviceSecretDto, id?: string) {
    this.scope(user);
    const recordId = id ?? randomUUID(),
      revision = randomUUID(),
      iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key(), iv);
    cipher.setAAD(context(user.id, recordId, input.purpose));
    const encrypted = Buffer.concat([cipher.update(input.value, "utf8"), cipher.final()]);
    const sealedValue = [iv, cipher.getAuthTag(), encrypted]
      .map((part) => part.toString("base64"))
      .join(".");
    try {
      await this.db.transaction(async (manager) => {
        if (id) {
          const existing = await manager.findOne(DeviceActionSecret, {
            where: { id, ownerId: user.id },
            lock: { mode: "pessimistic_write" },
          });
          if (!existing) throw new NotFoundException("راز در حساب شما پیدا نشد.");
          if (!input.revision || existing.revision !== input.revision)
            throw new ConflictException("راز هم‌زمان تغییر کرده است؛ فهرست را تازه‌سازی کنید.");
          if (existing.purpose !== input.purpose)
            throw new ConflictException("کاربرد راز موجود قابل تغییر نیست؛ مورد تازه بسازید.");
          await manager.update(
            DeviceActionSecret,
            { id, ownerId: user.id },
            { name: input.name, sealedValue, revision },
          );
        } else
          await manager.insert(DeviceActionSecret, {
            id: recordId,
            ownerId: user.id,
            purpose: input.purpose,
            name: input.name,
            sealedValue,
            revision,
          });
      });
    } catch (error) {
      if ((error as { driverError?: { code?: string } }).driverError?.code === "23505")
        throw new ConflictException("نام راز در این کاربرد تکراری است.");
      throw error;
    }
    return { id: recordId, name: input.name, purpose: input.purpose, revision };
  }
  async remove(user: AppUser, id: string, revision?: string) {
    this.scope(user);
    return this.db.transaction(async (manager) => {
      const record = await manager.findOne(DeviceActionSecret, {
        where: { id, ownerId: user.id },
        lock: { mode: "pessimistic_write" },
      });
      if (!record) throw new NotFoundException("راز در حساب شما پیدا نشد.");
      if (!revision || revision !== record.revision)
        throw new ConflictException("راز تغییر کرده است؛ فهرست را تازه‌سازی کنید.");
      await manager.delete(DeviceActionSecret, { id, ownerId: user.id });
      return { deleted: true };
    });
  }
  async snapshot(
    user: AppUser,
    id: string,
    purpose: DeviceActionSecret["purpose"],
    manager: EntityManager = this.db.manager,
    lock = false,
  ) {
    this.scope(user);
    const record = await manager.findOne(DeviceActionSecret, {
      where: { id, ownerId: user.id, purpose },
      select: { id: true, revision: true, sealedValue: true },
      ...(lock ? { lock: { mode: "pessimistic_read" as const } } : {}),
    });
    if (!record) throw new NotFoundException("راز با کاربرد لازم در حساب شما پیدا نشد.");
    try {
      const [iv, tag, data] = record.sealedValue
        .split(".")
        .map((value) => Buffer.from(value, "base64"));
      const decipher = createDecipheriv("aes-256-gcm", key(), iv);
      decipher.setAAD(context(user.id, id, purpose));
      decipher.setAuthTag(tag);
      const value = Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
      return { value, revision: record.revision };
    } catch {
      throw new ConflictException("راز رمزنگاری‌شده برای این حساب و کاربرد قابل خواندن نیست.");
    }
  }
}
