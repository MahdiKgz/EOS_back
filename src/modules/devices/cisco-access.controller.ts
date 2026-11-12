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
import type { AuthRequest } from "../auth/jwt-auth.guard";
import { CiscoAccessService } from "./cisco-access.service";
import { SaveCiscoAccessDto, SaveEnableCredentialDto } from "./cisco-access.dto";
@Controller("devices")
export class CiscoAccessController {
  constructor(private readonly access: CiscoAccessService) {}
  @Get("cisco-enable-credentials")
  @Header("Cache-Control", "private, no-store")
  credentials(@Req() req: AuthRequest) {
    return this.access.credentials(req.auth.user);
  }
  @Post("cisco-enable-credentials")
  @Header("Cache-Control", "private, no-store")
  create(@Req() req: AuthRequest, @Body() body: SaveEnableCredentialDto) {
    return this.access.saveCredential(req.auth.user, body);
  }
  @Put("cisco-enable-credentials/:id")
  @Header("Cache-Control", "private, no-store")
  edit(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Body() body: SaveEnableCredentialDto,
  ) {
    return this.access.saveCredential(req.auth.user, body, id);
  }
  @Delete("cisco-enable-credentials/:id")
  @Header("Cache-Control", "private, no-store")
  remove(@Req() req: AuthRequest, @Param("id", new ParseUUIDPipe({ version: "4" })) id: string) {
    return this.access.removeCredential(req.auth.user, id);
  }
  @Get(":id/cisco-access")
  @Header("Cache-Control", "private, no-store")
  get(@Req() req: AuthRequest, @Param("id", new ParseUUIDPipe({ version: "4" })) id: string) {
    return this.access.get(req.auth.user, id);
  }
  @Put(":id/cisco-access")
  @Header("Cache-Control", "private, no-store")
  save(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Body() body: SaveCiscoAccessDto,
  ) {
    return this.access.save(req.auth.user, id, body);
  }
}
