import { randomUUID } from "node:crypto";
import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryColumn,
  UpdateDateColumn,
} from "typeorm";

export enum AppUserRole {
  PLATFORM_ADMIN = "pl_admin",
  COMPANY_ADMIN = "co_admin",
  COMPANY_EMPLOYEE = "co_employee",
}

@Entity("app_users")
export class AppUser {
  @PrimaryColumn("text") id: string = randomUUID();
  @Column({ type: "varchar", length: 64, unique: true }) username!: string;
  @Column({ type: "varchar", length: 160, nullable: true, unique: true })
  email!: string | null;
  @Column({ type: "varchar", length: 24, nullable: true, unique: true })
  phone!: string | null;
  @Column({ type: "text", select: false }) passwordHash!: string;
  @Column({ type: "varchar", length: 80 }) displayName!: string;
  @Column({
    type: "enum",
    enum: AppUserRole,
    default: AppUserRole.COMPANY_EMPLOYEE,
  })
  role!: AppUserRole;
  @Column({ default: true }) isActive!: boolean;
  @Column({ type: "text", array: true, default: () => "'{}'" })
  allowedSections!: string[];
  @Index() @Column({ type: "text", nullable: true }) workspaceOwnerId!:
    | string
    | null;
  @CreateDateColumn({ type: "timestamptz" }) createdAt!: Date;
  @UpdateDateColumn({ type: "timestamptz" }) updatedAt!: Date;
}

export function publicUser(user: AppUser) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    email: user.email,
    phone: user.phone,
    role: user.role,
    isActive: user.isActive,
    allowedSections: user.allowedSections,
    workspaceOwnerId: user.workspaceOwnerId,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}
