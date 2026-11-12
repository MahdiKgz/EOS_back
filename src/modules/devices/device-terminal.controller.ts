import {
  Body,
  Controller,
  Get,
  Header,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
  Req,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import type { AuthRequest } from "../auth/jwt-auth.guard";
import { DeviceTerminalService } from "./device-terminal.service";
import {
  OpenTerminalDto,
  TerminalInputDto,
  TerminalReadDto,
  TerminalSizeDto,
} from "./terminal.dto";

@Controller("devices/:deviceId/terminal")
export class DeviceTerminalController {
  constructor(private readonly terminal: DeviceTerminalService) {}
  @Header("Cache-Control", "private, no-store")
  @Get()
  metadata(@Req() req: AuthRequest, @Param("deviceId", new ParseUUIDPipe()) id: string) {
    return this.terminal.metadata(req.auth, id);
  }
  @Header("Cache-Control", "private, no-store")
  @Post("preview")
  preview(@Req() req: AuthRequest, @Param("deviceId", new ParseUUIDPipe()) id: string) {
    return this.terminal.preview(req.auth, id);
  }
  @Header("Cache-Control", "private, no-store")
  @Post("sessions")
  open(
    @Req() req: AuthRequest,
    @Param("deviceId", new ParseUUIDPipe()) id: string,
    @Body() body: OpenTerminalDto,
  ) {
    return this.terminal.open(req.auth, id, body);
  }
  @Throttle({ default: { limit: 600, ttl: 60000 } })
  @Header("Cache-Control", "private, no-store")
  @Get("sessions/:sessionId")
  read(
    @Req() req: AuthRequest,
    @Param("deviceId", new ParseUUIDPipe()) id: string,
    @Param("sessionId", new ParseUUIDPipe()) sid: string,
    @Query() query: TerminalReadDto,
  ) {
    return this.terminal.read(req.auth, id, sid, query.cursor);
  }
  @Throttle({ default: { limit: 1200, ttl: 60000 } })
  @Header("Cache-Control", "private, no-store")
  @Post("sessions/:sessionId/input")
  input(
    @Req() req: AuthRequest,
    @Param("deviceId", new ParseUUIDPipe()) id: string,
    @Param("sessionId", new ParseUUIDPipe()) sid: string,
    @Body() body: TerminalInputDto,
  ) {
    return this.terminal.input(req.auth, id, sid, body.sequence, body.data);
  }
  @Header("Cache-Control", "private, no-store")
  @Post("sessions/:sessionId/resize")
  resize(
    @Req() req: AuthRequest,
    @Param("deviceId", new ParseUUIDPipe()) id: string,
    @Param("sessionId", new ParseUUIDPipe()) sid: string,
    @Body() body: TerminalSizeDto,
  ) {
    return this.terminal.resize(req.auth, id, sid, body.cols, body.rows);
  }
  @Header("Cache-Control", "private, no-store")
  @Post("sessions/:sessionId/close")
  close(
    @Req() req: AuthRequest,
    @Param("deviceId", new ParseUUIDPipe()) id: string,
    @Param("sessionId", new ParseUUIDPipe()) sid: string,
  ) {
    return this.terminal.close(req.auth, id, sid);
  }
}
