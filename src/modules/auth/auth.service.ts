import { createHash, randomBytes } from "node:crypto";
import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { InjectRepository } from "@nestjs/typeorm";
import { compare, hash } from "bcryptjs";
import { DataSource, MoreThan, Repository } from "typeorm";
import type { Environment } from "../../config/env";
import {
  AppUser,
  AppUserRole,
  publicUser,
} from "../users/user.entity";
import { AuthSession } from "./auth-session.entity";
import { PasswordReset } from "./password-reset.entity";
import { LoginDto, RegisterDto, ResetPasswordDto } from "./dto/auth.dto";
import { assertPasswordPolicy } from "./password-policy";
import { MailService } from "./mail.service";

type Claims = { sub: string; sid: string };
export type AuthenticatedSession = { user: AppUser; session: AuthSession };
const digest = (token: string) =>
  createHash("sha256").update(token).digest("hex");
const invalid = () =>
  new UnauthorizedException("نام کاربری یا رمز عبور اشتباه است.");

@Injectable()
export class AuthService {
  private readonly dummyHash = hash(randomBytes(32).toString("hex"), 12);
  constructor(
    @InjectRepository(AppUser) private readonly users: Repository<AppUser>,
    @InjectRepository(AuthSession)
    private readonly sessions: Repository<AuthSession>,
    @InjectRepository(PasswordReset)
    private readonly resets: Repository<PasswordReset>,
    private readonly db: DataSource,
    private readonly jwt: JwtService,
    private readonly config: ConfigService<Environment, true>,
    private readonly mail: MailService,
  ) {}

  async register(
    dto: RegisterDto,
    metadata: { userAgent?: string; ipAddress?: string },
  ) {
    assertPasswordPolicy(dto.password, dto.username);
    const passwordHash = await hash(dto.password, 12);
    try {
      return await this.db.transaction(async (manager) => {
        const user = await manager.save(
          AppUser,
          manager.create(AppUser, {
            username: dto.username,
            displayName: dto.displayName,
            email: dto.email ?? null,
            phone: dto.phone ?? null,
            passwordHash,
            role: AppUserRole.COMPANY_EMPLOYEE,
            isActive: true,
            allowedSections: [],
            workspaceOwnerId: null,
          }),
        );
        return this.createSession(manager, user, metadata);
      });
    } catch (error) {
      if (
        error &&
        typeof error === "object" &&
        "driverError" in error &&
        (error.driverError as { code?: string }).code === "23505"
      )
        throw new ConflictException(
          "نام کاربری، ایمیل یا تلفن واردشده قبلاً ثبت شده است.",
        );
      throw error;
    }
  }

  async login(
    dto: LoginDto,
    metadata: { userAgent?: string; ipAddress?: string },
  ) {
    const user = await this.users
      .createQueryBuilder("user")
      .addSelect("user.passwordHash")
      .where("user.username = :username", { username: dto.username })
      .getOne();
    const matches = await compare(
      dto.password,
      user?.passwordHash ?? (await this.dummyHash),
    );
    if (!user || !user.isActive || !matches) throw invalid();
    return this.db.transaction(async (manager) => {
      const current = await manager
        .createQueryBuilder(AppUser, "user")
        .addSelect("user.passwordHash")
        .setLock("pessimistic_read")
        .where("user.id = :id", { id: user.id })
        .getOne();
      if (!current?.isActive || current.passwordHash !== user.passwordHash)
        throw invalid();
      return this.createSession(manager, current, metadata);
    });
  }

  private async createSession(
    manager: import("typeorm").EntityManager,
    user: AppUser,
    metadata: { userAgent?: string; ipAddress?: string },
  ) {
    const session = manager.create(AuthSession, {
      userId: user.id,
      expiresAt: new Date(
        Date.now() + this.config.get("JWT_TTL_SECONDS", { infer: true }) * 1000,
      ),
      userAgent: metadata.userAgent?.slice(0, 500) ?? null,
      ipAddress: metadata.ipAddress?.slice(0, 64) ?? null,
      activeCompanyId: null,
      lastSeenAt: new Date(),
    });
    const accessToken = await this.jwt.signAsync({
      sub: user.id,
      sid: session.id,
    } satisfies Claims);
    session.tokenHash = digest(accessToken);
    await manager.save(session);
    return {
      user: publicUser(user),
      accessToken,
      expiresAt: session.expiresAt.toISOString(),
    };
  }

  async authenticateToken(token: string): Promise<AuthenticatedSession> {
    let claims: Claims;
    try {
      claims = await this.jwt.verifyAsync<Claims>(token);
    } catch {
      throw new UnauthorizedException("نشست شما معتبر نیست یا منقضی شده است.");
    }
    if (typeof claims.sub !== "string" || typeof claims.sid !== "string")
      throw new UnauthorizedException();
    const session = await this.sessions.findOne({
      where: {
        id: claims.sid,
        userId: claims.sub,
        tokenHash: digest(token),
        expiresAt: MoreThan(new Date()),
      },
      relations: { user: true },
    });
    if (!session || !session.user.isActive)
      throw new UnauthorizedException(
        "نشست شما پایان یافته است. دوباره وارد شوید.",
      );
    if (Date.now() - session.lastSeenAt.getTime() > 60000)
      await this.sessions.update(session.id, { lastSeenAt: new Date() });
    return { user: session.user, session };
  }

  async logout(sessionId: string) {
    await this.sessions.delete(sessionId);
    return { message: "از حساب کاربری خارج شدید." };
  }

  async forgetPassword(email: string) {
    this.mail.assertConfigured();
    const user = await this.users.findOneBy({ email, isActive: true });
    if (user) {
      const token = randomBytes(32).toString("hex");
      const reset = await this.resets.save(
        this.resets.create({
          userId: user.id,
          tokenHash: digest(token),
          expiresAt: new Date(Date.now() + 30 * 60000),
        }),
      );
      try {
        await this.mail.sendPasswordReset(email, token);
      } catch (error) {
        await this.resets.delete(reset.id);
        throw error;
      }
    }
    return {
      message:
        "اگر حسابی با این ایمیل ثبت شده باشد، لینک بازیابی برای آن ارسال می‌شود.",
    };
  }

  async resetPassword(dto: ResetPasswordDto) {
    const reset = await this.resets.findOneBy({
      tokenHash: digest(dto.token),
      expiresAt: MoreThan(new Date()),
    });
    if (!reset)
      throw new BadRequestException(
        "لینک بازیابی معتبر نیست یا منقضی شده است.",
      );
    const user = await this.users.findOneBy({
      id: reset.userId,
      isActive: true,
    });
    if (!user)
      throw new BadRequestException(
        "لینک بازیابی معتبر نیست یا منقضی شده است.",
      );
    assertPasswordPolicy(dto.password, user.username);
    const passwordHash = await hash(dto.password, 12);
    await this.db.transaction(async (manager) => {
      const current = await manager.findOne(AppUser, {
        where: { id: user.id, isActive: true },
        lock: { mode: "pessimistic_write" },
      });
      const validReset = await manager.findOneBy(PasswordReset, {
        id: reset.id,
        tokenHash: digest(dto.token),
        expiresAt: MoreThan(new Date()),
      });
      if (!current || !validReset)
        throw new BadRequestException(
          "لینک بازیابی معتبر نیست یا منقضی شده است.",
        );
      await manager.update(AppUser, user.id, { passwordHash });
      await manager.delete(PasswordReset, { userId: user.id });
      await manager.delete(AuthSession, { userId: user.id });
    });
    return { message: "رمز عبور تغییر کرد. با رمز جدید وارد شوید." };
  }
}
