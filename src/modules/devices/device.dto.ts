import { isIP } from "node:net";
import { Transform, Type } from "class-transformer";
import {
  ArrayMaxSize,
  ArrayUnique,
  IsArray,
  IsBoolean,
  IsDefined,
  ValidateNested,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  Length,
  Max,
  MaxLength,
  Min,
  ValidateBy,
} from "class-validator";
import { deviceTypes, environments, protocols, statuses } from "./device.entity";
import { LinuxSshDto } from "./linux-ssh";
const trim = ({ value }: { value: unknown }) => (typeof value === "string" ? value.trim() : value);
const lower = ({ value }: { value: unknown }) =>
  typeof value === "string" ? value.trim().toLowerCase() : value;
export class SaveDeviceDto {
  @IsOptional() @IsString() @Length(1, 64) companyId?: string;
  @IsOptional() @IsString() @Length(1, 64) credentialId?: string;
  @IsOptional() @IsIn(["direct"]) accessRoute?: "direct";

  @Transform(trim) @IsString() @Length(2, 120) name!: string;
  @Transform(lower) @IsString() @Length(1, 80) vendor!: string;
  @IsIn(deviceTypes) type!: (typeof deviceTypes)[number];
  @Transform(lower)
  @IsString()
  @MaxLength(253)
  @ValidateBy({
    name: "deviceHost",
    validator: {
      validate: (value: unknown) =>
        typeof value === "string" &&
        (isIP(value) !== 0 ||
          (/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(
            value,
          ) &&
            !/^[\d.]+$/.test(value))),
      defaultMessage: () => "آدرس IP یا نام میزبان معتبر وارد کنید.",
    },
  })
  host!: string;
  @IsInt() @Min(1) @Max(65535) managementPort!: number;
  @IsIn(protocols) protocol!: (typeof protocols)[number];
  @IsIn(environments) environment!: (typeof environments)[number];
  @IsArray()
  @ArrayMaxSize(25)
  @ArrayUnique()
  @IsString({ each: true })
  @Length(1, 40, { each: true })
  tags!: string[];
}
export class ListDevicesDto {
  @IsOptional() @Transform(trim) @IsString() @MaxLength(120) search?: string;
  @IsOptional() @IsIn(deviceTypes) type?: (typeof deviceTypes)[number];
  @IsOptional() @IsIn(statuses) status?: (typeof statuses)[number];
  @IsOptional() @IsIn(environments) environment?: (typeof environments)[number];
  @IsOptional() @IsIn(["network", "recorder"]) category?: "network" | "recorder";
  @IsOptional() @IsIn(["createdAt", "name", "host", "vendor", "status"]) sort: string = "createdAt";
  @IsOptional() @IsIn(["asc", "desc"]) direction: "asc" | "desc" = "desc";
  @Type(() => Number) @IsInt() @Min(1) @Max(100000) page: number = 1;
  @Type(() => Number) @IsInt() @Min(1) @Max(100) pageSize: number = 20;
}

export class RecorderConnectionDto {
  @Transform(trim) @IsString() @Length(1, 128) username!: string;
  @IsString() @Length(1, 1024) password!: string;
  @IsBoolean() https!: boolean;
}

export class DraftConnectionDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => SaveDeviceDto)
  device!: SaveDeviceDto;

  @IsOptional()
  @ValidateNested()
  @Type(() => LinuxSshDto)
  credentials?: LinuxSshDto;

  @IsOptional()
  @ValidateNested()
  @Type(() => RecorderConnectionDto)
  recorder?: RecorderConnectionDto;
}

export class CompanyNameDto {
  @Transform(trim) @IsString() @Length(2, 120) name!: string;
}

export class SaveCredentialDto extends LinuxSshDto {
  @Transform(trim) @IsString() @Length(2, 120) name!: string;
}
