import type { SecondaryChannelMethod } from "./device-channels.entity";
import { isIP } from "node:net";
import { Transform } from "class-transformer";
import {
  IsBoolean,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  Max,
  MaxLength,
  Min,
  MinLength,
  ValidateBy,
} from "class-validator";
export class SaveSnmpCredentialDto {
  @Transform(({ value }: { value: unknown }) => (typeof value === "string" ? value.trim() : value))
  @IsString()
  @MinLength(1)
  @MaxLength(120)
  name!: string;
  @IsString() @Matches(/^[a-zA-Z0-9_.-]{1,64}$/) username!: string;
  @IsIn(["SHA", "SHA256"]) authProtocol!: "SHA" | "SHA256";
  @IsString() @MinLength(8) @MaxLength(1024) @Matches(/^[^\r\n\0]+$/) authPassword!: string;
  @IsString() @MinLength(8) @MaxLength(1024) @Matches(/^[^\r\n\0]+$/) privacyPassword!: string;
}
export class SaveSecondaryChannelDto {
  @IsOptional() @IsUUID("4") revision?: string;
  @IsIn(["snmpv3", "ssh", "soap_api", "rest_api"]) method!: SecondaryChannelMethod;
  @IsUUID("4") credentialId!: string;
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    typeof value === "string" ? value.trim().toLowerCase() || undefined : value,
  )
  @IsString()
  @MaxLength(253)
  @ValidateBy({
    name: "channelHost",
    validator: {
      validate: (v: unknown) =>
        typeof v === "string" &&
        (isIP(v) !== 0 ||
          (/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(
            v,
          ) &&
            !/^[\d.]+$/.test(v))),
    },
  })
  host?: string;
  @IsInt() @Min(1) @Max(65535) port!: number;
  @IsInt() @IsIn([1, 2]) priority!: number;
}
export class ToggleSecondaryChannelDto {
  @IsBoolean() enabled!: boolean;
  @IsUUID("4") revision!: string;
}
