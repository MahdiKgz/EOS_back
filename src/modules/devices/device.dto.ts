import { CiscoRegistrationOptions } from "./cisco-access.dto";
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
  IsUUID,
  Length,
  Max,
  MaxLength,
  Min,
  ValidateBy,
} from "class-validator";
import { deviceTypes, environments, protocols, statuses } from "./device.entity";
import { LinuxSshDto } from "./linux-ssh";
import { recorderOnvifPath } from "./recorder-http";
const trim = ({ value }: { value: unknown }) => (typeof value === "string" ? value.trim() : value);
const lower = ({ value }: { value: unknown }) =>
  typeof value === "string" ? value.trim().toLowerCase() : value;
export class SaveDeviceDto {
  @IsOptional() @IsUUID("4") apiCredentialId?: string;
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
  @IsOptional() @Transform(trim) @IsString() @MaxLength(160) location?: string | null;
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
export class OnboardingDeviceDto extends SaveDeviceDto {
  @IsOptional()
  @ValidateNested()
  @Type(() => CiscoRegistrationOptions)
  ciscoProfile?: CiscoRegistrationOptions;
}
export class CreateDeviceDto extends OnboardingDeviceDto {
  @IsOptional() @IsUUID("4") draftRevision?: string;
  @IsOptional() @IsString() @Length(1, 14000) verificationToken?: string;
}
export class ListDevicesDto {
  @IsOptional() @IsUUID("4") companyId?: string;
  @IsOptional() @IsIn(["archived"]) inventory?: "archived";
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
export class AssetsOverviewQueryDto {
  @IsOptional() @IsUUID("4") companyId?: string;
  @IsOptional() @Transform(trim) @IsString() @MaxLength(120) search?: string;
  @IsOptional() @IsIn(["all", "online", "attention", "unverified"]) filter:
    "all" | "online" | "attention" | "unverified" = "all";
  @Type(() => Number) @IsInt() @Min(1) @Max(100000) page = 1;
  @Type(() => Number) @IsInt() @IsIn([10, 20, 50]) pageSize = 20;
}

const recorderModes = ["auto", "onvif", "appweb", "dvrip", "rtsp"] as const;
const validOnvifPath = () =>
  ValidateBy({
    name: "onvifPath",
    validator: {
      validate: (value: unknown) => {
        try {
          return typeof value === "string" && !!recorderOnvifPath(value);
        } catch {
          return false;
        }
      },
      defaultMessage: () => "مسیر سرویس ONVIF معتبر نیست.",
    },
  });

export class RecorderConnectionDto {
  @IsOptional() @IsString() @validOnvifPath() onvifPath?: string;
  @IsOptional() @IsIn(recorderModes) mode?: (typeof recorderModes)[number];
  @IsOptional() @IsString() @Length(1, 512) rtspPath?: string;
  @Transform(trim) @IsString() @Length(1, 128) username!: string;
  @IsString() @Length(1, 1024) password!: string;
  @IsBoolean() https!: boolean;
}

export class DiscoverRecordersDto {
  @IsString() @Length(1, 64) companyId!: string;
  @IsString() @Length(1, 32) @Transform(trim) cidr!: string;
  @IsInt() @Min(1) @Max(65535) port!: number;
  @IsBoolean() https!: boolean;
}

export class VerifyRecorderDto {
  @IsOptional() @IsString() @validOnvifPath() onvifPath?: string;
  @IsOptional() @IsIn(recorderModes) mode?: (typeof recorderModes)[number];
  @IsOptional() @IsString() @Length(1, 512) rtspPath?: string;
  @IsOptional() @IsBoolean() useSaved?: boolean;
  @IsOptional() @IsBoolean() saveConnection?: boolean;
  @IsOptional() @Transform(trim) @IsString() @Length(1, 128) username?: string;
  @IsOptional() @IsString() @Length(1, 1024) password?: string;
  @IsOptional() @IsBoolean() https?: boolean;
}

export class DraftConnectionDto {
  @IsOptional() @IsBoolean() saveRecorderConnection?: boolean;
  @IsDefined()
  @ValidateNested()
  @Type(() => OnboardingDeviceDto)
  device!: OnboardingDeviceDto;

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

export class RecorderSnapshotDto {
  @IsString() @Length(1, 256) token!: string;
}

class RegistrationDraftFieldsDto {
  @IsOptional()
  @ValidateNested()
  @Type(() => CiscoRegistrationOptions)
  ciscoProfile?: CiscoRegistrationOptions;
  @IsString() @MaxLength(120) name!: string;
  @IsString() @MaxLength(80) vendor!: string;
  @IsIn(deviceTypes) type!: (typeof deviceTypes)[number];
  @IsString() @MaxLength(253) host!: string;
  @IsInt() @Min(1) @Max(65535) managementPort!: number;
  @IsOptional() @IsString() @MaxLength(160) location?: string | null;
  @IsIn(protocols) protocol!: (typeof protocols)[number];
  @IsIn(environments) environment!: (typeof environments)[number];
  @IsString() @MaxLength(4096) tagsText!: string;
}

export class RegistrationDraftDto {
  @IsString() @MaxLength(64) companyId!: string;
  @IsIn(["network", "recorder"]) category!: "network" | "recorder";
  @IsDefined()
  @ValidateNested()
  @Type(() => RegistrationDraftFieldsDto)
  values!: RegistrationDraftFieldsDto;
}

export class BackupHistoryQueryDto {
  @IsOptional()
  @IsIn(["created", "failed", "downloaded", "file_deleted", "uploaded"])
  event?: "created" | "failed" | "downloaded" | "file_deleted" | "uploaded";

  @IsOptional() @Transform(trim) @IsString() @MaxLength(120) search?: string;
  @IsOptional() @Type(() => Number) @IsInt() @Min(1) @Max(100000) page: number = 1;
}

export class BackupHistorySelectionDto {
  @IsOptional()
  @IsIn(["created", "failed", "downloaded", "file_deleted", "uploaded"])
  event?: "created" | "failed" | "downloaded" | "file_deleted" | "uploaded";
  @IsOptional() @Transform(trim) @IsString() @MaxLength(120) search?: string;
  @IsOptional()
  @IsString()
  @ValidateBy({
    name: "eventId",
    validator: {
      validate: (value) =>
        typeof value === "string" &&
        /^[1-9][0-9]{0,18}$/.test(value) &&
        BigInt(value) <= 9223372036854775807n,
    },
  })
  eventId?: string;
}

export class ClearBackupHistoryDto {
  @IsString() @Length(1, 4096) selectionToken!: string;
}

export class BackupCatalogQueryDto {
  @IsOptional() @Transform(trim) @IsString() @MaxLength(120) search?: string;
  @IsOptional() @IsUUID("4") companyId?: string;
  @IsOptional() @IsIn(["collected", "uploaded"]) origin?: "collected" | "uploaded";
  @IsOptional() @Type(() => Number) @IsInt() @Min(1) @Max(100000) page: number = 1;
}
export class BackupActivityQueryDto extends BackupHistoryQueryDto {
  @IsOptional() @IsUUID("4") companyId?: string;
}
export class BackupActivitySelectionDto extends BackupHistorySelectionDto {
  @IsOptional() @IsUUID("4") companyId?: string;
}

export class PreviewDeviceRestoreDto {
  @IsUUID("4") artifactId!: string;
}
export class ExecuteDeviceRestoreDto {
  @IsIn(["execute"]) intent!: "execute";
  @IsString() @Length(64, 64) sha256!: string;
  @IsIn(["RESTORE BACKUP"]) confirmation!: "RESTORE BACKUP";
  @IsOptional() @IsIn(["RESTORE FULL ETC"]) fullEtcConfirmation?: "RESTORE FULL ETC";
}
