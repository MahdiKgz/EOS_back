import { Controller, Get, Header, Param, ParseUUIDPipe, Post, Req } from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import type { AuthRequest } from "../auth/jwt-auth.guard";
import { DeviceCapabilitiesService } from "./device-capabilities.service";
@Controller("devices/:id/capabilities")
export class DeviceCapabilitiesController {
  constructor(private readonly capabilities: DeviceCapabilitiesService) {}
  @Get()
  @Header("Cache-Control", "private, no-store")
  report(@Req() req: AuthRequest, @Param("id", new ParseUUIDPipe({ version: "4" })) id: string) {
    return this.capabilities.report(req.auth.user, id);
  }
  @Post("refresh")
  @Header("Cache-Control", "private, no-store")
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  refresh(@Req() req: AuthRequest, @Param("id", new ParseUUIDPipe({ version: "4" })) id: string) {
    return this.capabilities.refresh(req.auth.user, id);
  }
}
