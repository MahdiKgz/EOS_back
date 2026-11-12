import {
  Body,
  Controller,
  Delete,
  Get,
  Header,
  Param,
  ParseUUIDPipe,
  Post,
  Put,
  Req,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import type { AuthRequest } from "../auth/jwt-auth.guard";
import { VendorApiCredentialsService } from "./vendor-api-credentials.service";
import { InspectApiDto, SaveApiCredentialDto, UseApiCredentialDto } from "./vendor-api.dto";
import { DevicesService } from "./devices.service";
@Controller("devices")
export class VendorApiController {
  constructor(
    private readonly credentials: VendorApiCredentialsService,
    private readonly devices: DevicesService,
  ) {}
  @Get("api-credentials")
  @Header("Cache-Control", "private, no-store")
  list(@Req() req: AuthRequest) {
    return this.credentials.list(req.auth.user);
  }
  @Post("api-credentials")
  @Header("Cache-Control", "private, no-store")
  create(@Req() req: AuthRequest, @Body() body: SaveApiCredentialDto) {
    return this.credentials.save(req.auth.user, body);
  }
  @Put("api-credentials/:id")
  @Header("Cache-Control", "private, no-store")
  edit(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Body() body: SaveApiCredentialDto,
  ) {
    return this.credentials.save(req.auth.user, body, id);
  }
  @Delete("api-credentials/:id")
  @Header("Cache-Control", "private, no-store")
  remove(@Req() req: AuthRequest, @Param("id", new ParseUUIDPipe({ version: "4" })) id: string) {
    return this.credentials.remove(req.auth.user, id);
  }
  @Put(":id/api-credential")
  @Header("Cache-Control", "private, no-store")
  assign(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Body() body: UseApiCredentialDto,
  ) {
    return this.devices.assignApiCredential(req.auth.user, id, body.credentialId);
  }
  @Post(":id/esxi-inventory")
  @Header("Cache-Control", "private, no-store")
  @Throttle({ default: { limit: 20, ttl: 60000 } })
  inspect(@Req() req: AuthRequest, @Param("id", new ParseUUIDPipe({ version: "4" })) id: string) {
    return this.devices.verifySavedApi(req.auth.user, id, "esxi");
  }
  @Post(":id/esxi-ssh-inventory")
  @Header("Cache-Control", "private, no-store")
  @Throttle({ default: { limit: 20, ttl: 60000 } })
  inspectSsh(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
  ) {
    return this.devices.verifySavedEsxiSsh(req.auth.user, id);
  }
  @Post(":id/api-inventory")
  @Header("Cache-Control", "private, no-store")
  @Throttle({ default: { limit: 20, ttl: 60000 } })
  inspectApi(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Body() body: InspectApiDto,
  ) {
    return this.devices.verifySavedApi(req.auth.user, id, body.kind);
  }
}
