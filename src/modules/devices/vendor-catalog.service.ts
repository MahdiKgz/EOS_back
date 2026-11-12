import { ForbiddenException, Injectable, NotFoundException } from "@nestjs/common";
import { DataSource } from "typeorm";
import type { AppUser } from "../users/user.entity";
import { DeviceCompany } from "./device-onboarding.entity";
import { vendorCatalog } from "./vendor-catalog";
import { VendorCatalogQuery, VendorDevicesQuery } from "./vendor-catalog.dto";
// Canonical connector type wins over the free-form display name of the manufacturer.
const vendorCase = `CASE WHEN d."type"='linux_edge' THEN 'linux' WHEN d."type"='mikrotik' THEN 'mikrotik' WHEN d."type"='fortigate' THEN 'fortigate' WHEN d."type"='cisco' THEN 'cisco' WHEN d."type"='esxi' THEN 'esxi' WHEN d."type"='pfsense' THEN 'pfsense' WHEN d."type"='generic_firewall' AND d."vendor" ~* '^sophos([ _-]firewall)?$' THEN 'sophos' ELSE NULL END`;
@Injectable()
export class VendorCatalogService {
  constructor(private readonly db: DataSource) {}
  private async workspace(user: AppUser, companyId?: string) {
    if (user.allowedSections.length && !user.allowedSections.includes("assets"))
      throw new ForbiddenException("به دارایی‌ها دسترسی ندارید.");
    const workspace = user.workspaceOwnerId ?? user.id;
    if (
      companyId &&
      !(await this.db
        .getRepository(DeviceCompany)
        .existsBy({ id: companyId, workspaceOwnerId: workspace }))
    )
      throw new NotFoundException("شرکت در فضای کاری شما پیدا نشد.");
    return workspace;
  }
  async list(user: AppUser, input: VendorCatalogQuery) {
    const workspace = await this.workspace(user, input.companyId);
    const counts: { key: string; count: number }[] = await this.db.query(
      `SELECT ${vendorCase} AS key,count(*)::integer AS count FROM devices d WHERE d."workspaceOwnerId"=$1 AND d."deletedAt" IS NULL AND ($2::text IS NULL OR d."companyId"=$2) GROUP BY key`,
      [workspace, input.companyId ?? null],
    );
    const items = vendorCatalog.map((v) => ({
      ...v,
      deviceCount: counts.find((c) => c.key === v.key)?.count ?? 0,
    }));
    const stats = { implemented: 0, partial: 0, planned: 0, unsupported: 0 };
    for (const item of items) stats[item.state]++;
    return {
      items: items.filter(
        (item) =>
          (!input.state || item.state === input.state) &&
          (!input.search ||
            [item.title, item.key, item.description].some((value) =>
              value.toLocaleLowerCase().includes(input.search!.toLocaleLowerCase()),
            )),
      ),
      stats,
      total: items.length,
    };
  }
  async detail(user: AppUser, key: string, input: VendorDevicesQuery) {
    const vendor = vendorCatalog.find((v) => v.key === key);
    if (!vendor) throw new NotFoundException("وندور پیدا نشد.");
    const workspace = await this.workspace(user, input.companyId),
      search = input.search ? `%${input.search.replace(/[\\%_]/g, "\\$&")}%` : null;
    const params = [workspace, input.companyId ?? null, key, search, input.status ?? null];
    const where = `d."workspaceOwnerId"=$1 AND d."deletedAt" IS NULL AND ($2::text IS NULL OR d."companyId"=$2) AND ${vendorCase}=$3`;
    const filter = `AND ($4::text IS NULL OR d."name" ILIKE $4 ESCAPE '\\' OR d."host" ILIKE $4 ESCAPE '\\' OR d."vendor" ILIKE $4 ESCAPE '\\' OR d."location" ILIKE $4 ESCAPE '\\') AND ($5::text IS NULL OR d."status"=$5)`;
    const [counts] = await this.db.query(
      `SELECT count(*)::integer AS total,count(*) FILTER(WHERE d."status"='online')::integer AS online FROM devices d WHERE ${where}`,
      params.slice(0, 3),
    );
    const [filtered] = await this.db.query(
      `SELECT count(*)::integer AS total FROM devices d WHERE ${where} ${filter}`,
      params,
    );
    const items = await this.db.query(
      `SELECT d."id",d."name",d."type",d."vendor",d."host",d."managementPort",d."protocol",d."status",d."lastSeenAt",d."updatedAt",d."companyId",c."name" AS "companyName",(d."verification" IS NOT NULL) AS verified,
        cache."snapshot"->'detection'->>'platform' AS platform,cache."collectedAt" AS "platformCollectedAt"
        FROM devices d LEFT JOIN device_companies c ON c."id"=d."companyId" AND c."workspaceOwnerId"=$1
        LEFT JOIN device_capability_cache cache ON d."type" IN ('cisco','fortigate') AND d."protocol"='ssh' AND cache."snapshot"->'detection'->>'vendor'=d."type" AND cache."deviceId"=d."id" AND cache."companyId" IS NOT DISTINCT FROM d."companyId" AND cache."snapshot"->'source'->>'host'=d."host" AND (cache."snapshot"->'source'->>'port')::integer=d."managementPort" WHERE ${where} ${filter} ORDER BY d."updatedAt" DESC,d."id" ASC LIMIT $6 OFFSET $7`,
      [...params, input.pageSize, (input.page - 1) * input.pageSize],
    );
    return {
      vendor,
      stats: counts,
      devices: { items, total: filtered.total, page: input.page, pageSize: input.pageSize },
    };
  }
}
