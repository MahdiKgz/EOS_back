import { randomUUID } from "node:crypto";
import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryColumn,
} from "typeorm";
import { AppUser } from "../users/user.entity";

@Entity("auth_sessions")
export class AuthSession {
  @PrimaryColumn("text") id: string = randomUUID();
  @Index() @Column("text") userId!: string;
  @ManyToOne(() => AppUser, { onDelete: "CASCADE" })
  @JoinColumn({ name: "userId" })
  user!: AppUser;
  @Column({ type: "text", unique: true }) tokenHash!: string;
  @Column({ type: "text", nullable: true }) activeCompanyId!: string | null;
  @Index() @Column({ type: "timestamptz" }) expiresAt!: Date;
  @CreateDateColumn({ type: "timestamptz" }) createdAt!: Date;
  @Column({ type: "timestamptz", default: () => "CURRENT_TIMESTAMP" })
  lastSeenAt!: Date;
  @Column({ type: "varchar", length: 500, nullable: true }) userAgent!:
    | string
    | null;
  @Column({ type: "varchar", length: 64, nullable: true }) ipAddress!:
    | string
    | null;
}
