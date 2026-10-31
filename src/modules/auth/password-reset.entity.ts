import { randomUUID } from "node:crypto";
import { Column, CreateDateColumn, Entity, Index, JoinColumn, ManyToOne, PrimaryColumn } from "typeorm";
import { AppUser } from "../users/user.entity";

@Entity("password_resets")
export class PasswordReset {
  @PrimaryColumn("text") id: string = randomUUID();
  @Index() @Column("text") userId!: string;
  @ManyToOne(() => AppUser, { onDelete: "CASCADE" }) @JoinColumn({ name: "userId" }) user!: AppUser;
  @Column({ type: "text", unique: true }) tokenHash!: string;
  @Column({ type: "timestamptz" }) expiresAt!: Date;
  @CreateDateColumn({ type: "timestamptz" }) createdAt!: Date;
}
