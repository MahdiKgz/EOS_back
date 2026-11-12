import { Transform } from "class-transformer";
import { IsIn, IsOptional, IsString, IsUUID, Length, Matches } from "class-validator";
export class SaveEnableCredentialDto {
  @Transform(({ value }: { value: unknown }) => (typeof value === "string" ? value.trim() : value))
  @IsString()
  @Length(2, 120)
  name!: string;
  @IsString() @Length(1, 1024) @Matches(/^[^\r\n\0]+$/) password!: string;
}
export class CiscoRegistrationOptions {
  @IsIn(["modern", "legacy_cisco"]) compatibilityProfile!: "modern" | "legacy_cisco";
  @IsOptional() @IsUUID("4") enableCredentialId?: string | null;
}
export class SaveCiscoAccessDto extends CiscoRegistrationOptions {
  @IsOptional() @IsUUID("4") revision?: string;
}
