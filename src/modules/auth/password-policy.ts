import { BadRequestException } from "@nestjs/common";
const common = new Set([
  "123456789012",
  "admin12345678",
  "password1234",
  "qwerty123456",
  "letmein123456",
]);
export function assertPasswordPolicy(password: string, username: string) {
  if (password.length < 12 || password.length > 128 || Buffer.byteLength(password, "utf8") > 72)
    throw new BadRequestException(
      "رمز عبور باید حداقل ۱۲ کاراکتر داشته باشد و بیش از حد طولانی نباشد.",
    );
  if (common.has(password.toLowerCase()) || password.toLowerCase().includes(username.toLowerCase()))
    throw new BadRequestException("رمز عبور رایج یا شامل نام کاربری قابل استفاده نیست.");
}
