import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { Request } from "express";
import { AuthService, type AuthenticatedSession } from "./auth.service";
import { IS_PUBLIC } from "./public.decorator";
export type AuthRequest = Request & { auth: AuthenticatedSession };
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly authService: AuthService,
  ) {}
  async canActivate(context: ExecutionContext) {
    if (
      this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, [
        context.getHandler(),
        context.getClass(),
      ])
    )
      return true;
    const req = context.switchToHttp().getRequest<AuthRequest>();
    const match = /^Bearer ([^\s]+)$/.exec(req.headers.authorization ?? "");
    if (!match) throw new UnauthorizedException("برای دسترسی وارد حساب کاربری شوید.");
    req.auth = await this.authService.authenticateToken(match[1]);
    return true;
  }
}
