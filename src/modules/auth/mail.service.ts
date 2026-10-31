import { Injectable, ServiceUnavailableException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { createTransport } from "nodemailer";
import type { Environment } from "../../config/env";
@Injectable()
export class MailService {
  constructor(private readonly config: ConfigService<Environment, true>) {}
  assertConfigured() {
    if (!this.config.get("SMTP_HOST", { infer: true })) throw new ServiceUnavailableException("ارسال ایمیل بازیابی در حال حاضر در دسترس نیست.");
  }
  async sendPasswordReset(email: string, token: string) {
    this.assertConfigured();
    const username = this.config.get("SMTP_USERNAME", { infer: true });
    const transport = createTransport({
      host: this.config.get("SMTP_HOST", { infer: true }), port: this.config.get("SMTP_PORT", { infer: true }),
      secure: this.config.get("SMTP_SECURE", { infer: true }),
      auth: username ? { user: username, pass: this.config.get("SMTP_PASSWORD", { infer: true }) } : undefined,
      connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000,
    });
    const url = new URL("/reset-password", this.config.get("APP_URL", { infer: true }));
    url.searchParams.set("token", token);
    try {
      await transport.sendMail({ from: this.config.get("SMTP_FROM", { infer: true }), to: email,
        subject: "بازیابی رمز عبور EOSNet", text: `برای تعیین رمز عبور جدید، لینک زیر را باز کنید. این لینک ۳۰ دقیقه اعتبار دارد و تنها یک بار قابل استفاده است.\n\n${url.toString()}\n\nاگر این درخواست را ثبت نکرده‌اید، این ایمیل را نادیده بگیرید.` });
    } catch { throw new ServiceUnavailableException("ارسال ایمیل بازیابی انجام نشد. کمی بعد دوباره تلاش کنید."); }
    finally { transport.close(); }
  }
}
