import {
  Body,
  Controller,
  Get,
  Header,
  Param,
  ParseUUIDPipe,
  Post,
  Put,
  Query,
  Req,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import type { AuthRequest } from "../auth/jwt-auth.guard";
import { DeviceMonitoringService } from "./device-monitoring.service";
import { MonitoringQueryDto, SaveMonitoringDto } from "./monitoring.dto";
@Controller("devices/:id/monitoring")
export class DeviceMonitoringController {
  constructor(private readonly monitoring: DeviceMonitoringService) {}
  @Get()
  @Header("Cache-Control", "private, no-store")
  report(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Query() query: MonitoringQueryDto,
  ) {
    return this.monitoring.report(req.auth.user, id, query);
  }
  @Put()
  @Header("Cache-Control", "private, no-store")
  configure(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Body() body: SaveMonitoringDto,
  ) {
    return this.monitoring.configure(req.auth.user, id, body);
  }
  @Post("collect")
  @Header("Cache-Control", "private, no-store")
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  collect(@Req() req: AuthRequest, @Param("id", new ParseUUIDPipe({ version: "4" })) id: string) {
    return this.monitoring.collect(req.auth.user, id);
  }
}
