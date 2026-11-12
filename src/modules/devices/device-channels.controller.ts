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
import { DeviceChannelsService } from "./device-channels.service";
import {
  SaveSecondaryChannelDto,
  SaveSnmpCredentialDto,
  ToggleSecondaryChannelDto,
} from "./device-channels.dto";
@Controller("devices")
export class DeviceChannelsController {
  constructor(private readonly channels: DeviceChannelsService) {}
  @Header("Cache-Control", "private, no-store")
  @Get("snmp-credentials")
  credentials(@Req() req: AuthRequest) {
    return this.channels.credentials(req.auth.user);
  }
  @Header("Cache-Control", "private, no-store")
  @Post("snmp-credentials")
  save(@Req() req: AuthRequest, @Body() body: SaveSnmpCredentialDto) {
    return this.channels.saveCredential(req.auth.user, body);
  }
  @Header("Cache-Control", "private, no-store")
  @Put("snmp-credentials/:id")
  edit(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Body() body: SaveSnmpCredentialDto,
  ) {
    return this.channels.saveCredential(req.auth.user, body, id, true);
  }
  @Header("Cache-Control", "private, no-store")
  @Delete("snmp-credentials/:id")
  remove(@Req() req: AuthRequest, @Param("id", new ParseUUIDPipe({ version: "4" })) id: string) {
    return this.channels.deleteCredential(req.auth.user, id);
  }
  @Header("Cache-Control", "private, no-store")
  @Get(":id/connection-channels")
  list(@Req() req: AuthRequest, @Param("id", new ParseUUIDPipe({ version: "4" })) id: string) {
    return this.channels.list(req.auth.user, id);
  }
  @Header("Cache-Control", "private, no-store")
  @Put(":id/connection-channels")
  configure(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Body() body: SaveSecondaryChannelDto,
  ) {
    return this.channels.configure(req.auth.user, id, body);
  }
  @Header("Cache-Control", "private, no-store")
  @Put(":id/connection-channels/state")
  toggle(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Body() body: ToggleSecondaryChannelDto,
  ) {
    return this.channels.toggle(req.auth.user, id, body);
  }
  @Header("Cache-Control", "private, no-store")
  @Post(":id/connection-channels/test-primary")
  @Throttle({ default: { limit: 20, ttl: 60000 } })
  testPrimary(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
  ) {
    return this.channels.testPrimary(req.auth.user, id);
  }
  @Header("Cache-Control", "private, no-store")
  @Post(":id/connection-channels/test-secondary")
  @Throttle({ default: { limit: 20, ttl: 60000 } })
  testSecondary(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
  ) {
    return this.channels.testSecondary(req.auth.user, id);
  }
}
