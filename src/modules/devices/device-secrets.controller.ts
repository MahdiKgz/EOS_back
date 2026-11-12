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
import { Transform } from "class-transformer";
import { IsIn, IsOptional, IsString, IsUUID, Length, Matches } from "class-validator";
import type { AuthRequest } from "../auth/jwt-auth.guard";
import { DeviceSecretsService } from "./device-secrets.service";
export class SaveDeviceSecretDto {
  @Transform(({ value }: { value: unknown }) => (typeof value === "string" ? value.trim() : value))
  @IsString()
  @Length(2, 120)
  name!: string;
  @IsIn(["admin_password", "ipsec_psk"]) purpose!: "admin_password" | "ipsec_psk";
  @IsString() @Length(1, 2048) @Matches(/^[^\p{Cc}]+$/u) value!: string;
  @IsOptional() @IsUUID("4") revision?: string;
}
export class RemoveDeviceSecretDto {
  @IsUUID("4") revision!: string;
}
@Controller("devices/action-secrets")
export class DeviceSecretsController {
  constructor(private readonly secrets: DeviceSecretsService) {}
  @Get() @Header("Cache-Control", "private, no-store") list(@Req() req: AuthRequest) {
    return this.secrets.list(req.auth.user);
  }
  @Post() @Header("Cache-Control", "private, no-store") create(
    @Req() req: AuthRequest,
    @Body() body: SaveDeviceSecretDto,
  ) {
    return this.secrets.save(req.auth.user, body);
  }
  @Put(":id") @Header("Cache-Control", "private, no-store") update(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Body() body: SaveDeviceSecretDto,
  ) {
    return this.secrets.save(req.auth.user, body, id);
  }
  @Delete(":id") @Header("Cache-Control", "private, no-store") remove(
    @Req() req: AuthRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Body() body: RemoveDeviceSecretDto,
  ) {
    return this.secrets.remove(req.auth.user, id, body.revision);
  }
}
