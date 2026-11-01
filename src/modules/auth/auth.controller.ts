import { Body, Controller, Get, Header, HttpCode, Post, Req } from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import type { Request } from "express";
import { publicUser } from "../users/user.entity";
import { AuthService } from "./auth.service";
import { ForgetPasswordDto, LoginDto, RegisterDto, ResetPasswordDto } from "./dto/auth.dto";
import type { AuthRequest } from "./jwt-auth.guard";
import { Public } from "./public.decorator";

@Controller("auth")
export class AuthController {
  constructor(private readonly auth: AuthService) {}
  private metadata(req: Request) {
    return { userAgent: req.headers["user-agent"], ipAddress: req.ip };
  }
  @Public()
  @Post("register")
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Header("Cache-Control", "no-store")
  register(@Body() dto: RegisterDto, @Req() req: Request) {
    return this.auth.register(dto, this.metadata(req));
  }
  @Public()
  @Post("login")
  @HttpCode(200)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Header("Cache-Control", "no-store")
  login(@Body() dto: LoginDto, @Req() req: Request) {
    return this.auth.login(dto, this.metadata(req));
  }
  @Get("me")
  @Header("Cache-Control", "no-store")
  me(@Req() req: AuthRequest) {
    return { user: publicUser(req.auth.user) };
  }
  @Post("logout")
  @HttpCode(200)
  @Header("Cache-Control", "no-store")
  logout(@Req() req: AuthRequest) {
    return this.auth.logout(req.auth.session.id);
  }
  @Public()
  @Post("forget-password")
  @HttpCode(200)
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  forget(@Body() dto: ForgetPasswordDto) {
    return this.auth.forgetPassword(dto.email);
  }
  @Public()
  @Post("reset-password")
  @HttpCode(200)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  reset(@Body() dto: ResetPasswordDto) {
    return this.auth.resetPassword(dto);
  }
}
