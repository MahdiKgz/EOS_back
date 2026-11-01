import { Transform } from "class-transformer";
import { IsEmail, IsOptional, IsString, Length, Matches, MaxLength } from "class-validator";
const normalize = ({ value }: { value: unknown }) =>
  typeof value === "string" ? value.trim().toLowerCase() : value;
const optionalContact = ({ value }: { value: unknown }) =>
  typeof value === "string" ? value.trim().toLowerCase() || undefined : value;
export class LoginDto {
  @Transform(normalize) @IsString() @Length(3, 64) username!: string;
  @IsString() @Length(1, 128) password!: string;
}
export class RegisterDto {
  @Transform(normalize)
  @IsString()
  @Matches(/^[a-z0-9][a-z0-9._-]{2,63}$/, {
    message: "نام کاربری باید ۳ تا ۶۴ کاراکتر انگلیسی، عدد، نقطه، خط تیره یا زیرخط باشد.",
  })
  username!: string;
  @Transform(({ value }: { value: unknown }) => (typeof value === "string" ? value.trim() : value))
  @IsString()
  @Length(2, 80)
  displayName!: string;
  @Transform(optionalContact)
  @IsOptional()
  @IsEmail()
  @MaxLength(160)
  email?: string;
  @Transform(optionalContact)
  @IsOptional()
  @Matches(/^\+?[0-9]{7,20}$/, { message: "شماره تلفن معتبر وارد کنید." })
  phone?: string;
  @IsString() @Length(12, 128) password!: string;
}
export class ForgetPasswordDto {
  @Transform(normalize) @IsEmail() @MaxLength(160) email!: string;
}
export class ResetPasswordDto {
  @IsString() @Matches(/^[a-f0-9]{64}$/) token!: string;
  @IsString() @Length(12, 128) password!: string;
}
