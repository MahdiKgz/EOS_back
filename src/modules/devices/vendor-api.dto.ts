import { X509Certificate } from "node:crypto";
import { Transform } from "class-transformer";
import {
  IsOptional,
  IsIn,
  IsString,
  IsUUID,
  Length,
  Matches,
  MaxLength,
  ValidateBy,
} from "class-validator";
export class SaveApiCredentialDto {
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    typeof value === "string"
      ? value
          .trim()
          .replace(/^SHA256:/i, "")
          .replace(/:/g, "")
          .toUpperCase() || undefined
      : value,
  )
  @IsString()
  @Matches(/^[A-F0-9]{64}$/)
  tlsFingerprint?: string;
  @Transform(({ value }: { value: unknown }) => (typeof value === "string" ? value.trim() : value))
  @IsString()
  @Length(2, 120)
  name!: string;
  @IsString() @Length(1, 128) @Matches(/^[^\r\n\0]+$/) username!: string;
  @IsString() @Length(1, 1024) @Matches(/^[^\r\n\0]+$/) password!: string;
  @IsOptional()
  @IsString()
  @MaxLength(16384)
  @ValidateBy({
    name: "apiCertificate",
    validator: {
      validate: (value: unknown) => {
        if (value === "") return true;
        if (
          typeof value !== "string" ||
          !/^\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*$/.test(
            value,
          )
        )
          return false;
        try {
          new X509Certificate(value);
          return true;
        } catch {
          return false;
        }
      },
      defaultMessage: () => "یک گواهی عمومی PEM معتبر وارد کنید.",
    },
  })
  caCertificate?: string;
}
export class UseApiCredentialDto {
  @IsUUID("4") credentialId!: string;
}
export class InspectApiDto {
  @IsOptional()
  @IsIn(["esxi", "mikrotik", "sophos"])
  kind?: "esxi" | "mikrotik" | "sophos";
}
