import {
  Body,
  Controller,
  Delete,
  Get,
  Header,
  Param,
  Post,
  Put,
  Query,
  Req,
} from "@nestjs/common";
import type { AuthRequest } from "../auth/jwt-auth.guard";
import {
  CompanyNameDto,
  SaveCredentialDto,
  DraftConnectionDto,
  ListDevicesDto,
  SaveDeviceDto,
} from "./device.dto";
import { LinuxSshDto } from "./linux-ssh";
import { DevicesService } from "./devices.service";
@Controller("devices")
export class DevicesController {
  constructor(private readonly devices: DevicesService) {}
  @Header("Cache-Control", "private, no-store") @Get() list(
    @Req() req: AuthRequest,
    @Query() query: ListDevicesDto,
  ) {
    return this.devices.list(req.auth.user, query);
  }
  @Get("companies")
  @Header("Cache-Control", "private, no-store")
  companies(@Req() req: AuthRequest) {
    return this.devices.companies(req.auth.user);
  }
  @Post("companies")
  createCompany(@Req() req: AuthRequest, @Body() body: CompanyNameDto) {
    return this.devices.createCompany(req.auth.user, body.name);
  }
  @Get("credentials")
  @Header("Cache-Control", "private, no-store")
  credentials(@Req() req: AuthRequest) {
    return this.devices.credentials(req.auth.user);
  }
  @Post("credentials")
  createCredential(@Req() req: AuthRequest, @Body() body: SaveCredentialDto) {
    return this.devices.saveCredential(req.auth.user, body);
  }
  @Put("credentials/:id")
  editCredential(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Body() body: SaveCredentialDto,
  ) {
    return this.devices.saveCredential(req.auth.user, body, id);
  }
  @Delete("credentials/:id")
  deleteCredential(@Req() req: AuthRequest, @Param("id") id: string) {
    return this.devices.deleteCredential(req.auth.user, id);
  }
  @Header("Cache-Control", "private, no-store") @Get(":id") get(
    @Req() req: AuthRequest,
    @Param("id") id: string,
  ) {
    return this.devices.get(req.auth.user, id);
  }
  @Get(":id/history")
  @Header("Cache-Control", "private, no-store")
  history(@Req() req: AuthRequest, @Param("id") id: string) {
    return this.devices.history(req.auth.user, id);
  }
  @Post("draft-connection")
  @Header("Cache-Control", "private, no-store")
  testDraft(@Req() req: AuthRequest, @Body() body: DraftConnectionDto) {
    return this.devices.testDraftConnection(req.auth.user, body);
  }
  @Post() create(@Req() req: AuthRequest, @Body() body: SaveDeviceDto) {
    return this.devices.create(req.auth.user, body);
  }
  @Post(":id/test-connection")
  testConnection(@Req() req: AuthRequest, @Param("id") id: string) {
    return this.devices.testConnection(req.auth.user, id);
  }
  @Post(":id/linux-ssh")
  @Header("Cache-Control", "private, no-store")
  linuxSsh(@Req() req: AuthRequest, @Param("id") id: string, @Body() body: LinuxSshDto) {
    return this.devices.linuxSsh(req.auth.user, id, body);
  }
  @Put(":id") update(
    @Req() req: AuthRequest,
    @Param("id") id: string,
    @Body() body: SaveDeviceDto,
  ) {
    return this.devices.update(req.auth.user, id, body);
  }
  @Delete(":id") archive(@Req() req: AuthRequest, @Param("id") id: string) {
    return this.devices.archive(req.auth.user, id);
  }
}
