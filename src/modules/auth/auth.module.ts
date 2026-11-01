import { Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtModule } from "@nestjs/jwt";
import { TypeOrmModule } from "@nestjs/typeorm";
import type { Environment } from "../../config/env";
import { AppUser } from "../users/user.entity";
import { AuthSession } from "./auth-session.entity";
import { PasswordReset } from "./password-reset.entity";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { MailService } from "./mail.service";
@Module({
  imports: [
    TypeOrmModule.forFeature([AppUser, AuthSession, PasswordReset]),
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<Environment, true>) => ({
        secret: config.get("JWT_SECRET", { infer: true }),
        signOptions: {
          algorithm: "HS256",
          expiresIn: config.get("JWT_TTL_SECONDS", { infer: true }),
          issuer: "eosnet",
          audience: "eosnet-web",
        },
        verifyOptions: { algorithms: ["HS256"], issuer: "eosnet", audience: "eosnet-web" },
      }),
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, MailService],
  exports: [AuthService],
})
export class AuthModule {}
