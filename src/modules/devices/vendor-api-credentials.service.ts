import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import { DataSource, EntityManager } from "typeorm";
import { randomUUID } from "node:crypto";
import type { AppUser } from "../users/user.entity";
import { DeviceApiCredential } from "./vendor-api-credential.entity";
import { SaveApiCredentialDto } from "./vendor-api.dto";
import { sealApiCredentials, unsealApiCredentials } from "./ssh-credential-vault";
@Injectable()
export class VendorApiCredentialsService {
  constructor(private readonly db: DataSource) {}
  private authorize(user: AppUser) {
    if (user.allowedSections.length && !user.allowedSections.includes("assets"))
      throw new ForbiddenException("به دارایی‌ها دسترسی ندارید.");
  }
  list(user: AppUser) {
    this.authorize(user);
    return this.db
      .getRepository(DeviceApiCredential)
      .find({ where: { ownerId: user.id }, order: { name: "ASC" } });
  }
  async get(user: AppUser, id: string, manager: EntityManager = this.db.manager, lock = false) {
    this.authorize(user);
    const entry = await manager.getRepository(DeviceApiCredential).findOne({
      where: { id, ownerId: user.id },
      select: { id: true, sealedCredentials: true },
      ...(lock ? { lock: { mode: "pessimistic_read" as const } } : {}),
    });
    if (!entry) throw new NotFoundException("اعتبارنامهٔ API در حساب شما پیدا نشد.");
    return entry;
  }
  secret(user: AppUser, entry: Pick<DeviceApiCredential, "id" | "sealedCredentials">) {
    return unsealApiCredentials(user.id, entry.id, entry.sealedCredentials);
  }
  async save(user: AppUser, input: SaveApiCredentialDto, id?: string) {
    this.authorize(user);
    if (id) await this.get(user, id);
    if (input.caCertificate && input.tlsFingerprint)
      throw new BadRequestException("یکی از گواهی عمومی یا اثر انگشت TLS را انتخاب کنید.");
    const credentialId = id ?? randomUUID();
    const row = {
      id: credentialId,
      ownerId: user.id,
      name: input.name,
      username: input.username,
      sealedCredentials: sealApiCredentials(user.id, credentialId, {
        username: input.username,
        password: input.password,
        caCertificate: input.caCertificate || undefined,
        tlsFingerprint: input.tlsFingerprint,
      }),
    };
    await this.db.transaction(async (manager) => {
      if (id) {
        // Parent rows precede credential locks, matching connection verification.
        await manager.query(
          `SELECT "id" FROM "devices" WHERE "apiCredentialId"=$1 ORDER BY "id" FOR UPDATE`,
          [id],
        );
        const result = await manager.update(DeviceApiCredential, { id, ownerId: user.id }, row);
        if (!result.affected) throw new NotFoundException("اعتبارنامه پیدا نشد.");
        await manager.query(`UPDATE "devices" SET "verification"=NULL WHERE "apiCredentialId"=$1`, [
          id,
        ]);
      } else await manager.insert(DeviceApiCredential, row);
    });
    return { id: credentialId, name: row.name, username: row.username };
  }
  async remove(user: AppUser, id: string) {
    this.authorize(user);
    await this.get(user, id);
    await this.db.transaction(async (manager) => {
      await manager.query(
        `SELECT "id" FROM "devices" WHERE "apiCredentialId"=$1 ORDER BY "id" FOR UPDATE`,
        [id],
      );
      await this.get(user, id, manager);
      await manager.query(`UPDATE "devices" SET "verification"=NULL WHERE "apiCredentialId"=$1`, [
        id,
      ]);
      await manager.delete(DeviceApiCredential, { id, ownerId: user.id });
    });
    return { deleted: true };
  }
}
