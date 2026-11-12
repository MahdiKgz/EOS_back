import { Controller, Get, Header, Param, Query, Req } from "@nestjs/common";
import type { AuthRequest } from "../auth/jwt-auth.guard";
import { VendorCatalogService } from "./vendor-catalog.service";
import { VendorCatalogQuery, VendorDevicesQuery } from "./vendor-catalog.dto";
@Controller("vendors")
export class VendorCatalogController {
  constructor(private readonly catalog: VendorCatalogService) {}
  @Get()
  @Header("Cache-Control", "private, no-store")
  list(@Req() req: AuthRequest, @Query() query: VendorCatalogQuery) {
    return this.catalog.list(req.auth.user, query);
  }
  @Get(":key")
  @Header("Cache-Control", "private, no-store")
  detail(@Req() req: AuthRequest, @Param("key") key: string, @Query() query: VendorDevicesQuery) {
    return this.catalog.detail(req.auth.user, key, query);
  }
}
