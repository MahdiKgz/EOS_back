import { Body, Controller, Get, Header, Param, ParseUUIDPipe, Post, Req } from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import type { AuthRequest } from "../auth/jwt-auth.guard";
import { DeviceActionsService } from "./device-actions.service";
import { PreviewFortiActionDto, ExecuteFortiActionDto } from "./fortigate-actions.dto";
@Controller("devices/:id/actions")
export class DeviceActionsController {
  constructor(private readonly service: DeviceActionsService) {}
  @Get() @Header("Cache-Control", "private, no-store") list(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
  ) {
    return this.service.list(req.auth.user, id);
  }
  @Post("preview")
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Header("Cache-Control", "private, no-store")
  preview(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Body() body: PreviewFortiActionDto,
  ) {
    return this.service.preview(req.auth.user, id, body);
  }
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Post(":plan/verify")
  @Header("Cache-Control", "private, no-store")
  verify(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Param("plan", new ParseUUIDPipe({ version: "4" })) plan: string,
  ) {
    return this.service.verify(req.auth.user, id, plan);
  }
  @Post(":plan/execute") @Header("Cache-Control", "private, no-store") execute(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Param("plan", new ParseUUIDPipe({ version: "4" })) plan: string,
    @Body() body: ExecuteFortiActionDto,
  ) {
    return this.service.execute(req.auth.user, id, plan, body);
  }
}
