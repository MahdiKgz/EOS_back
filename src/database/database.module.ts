import { Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { TypeOrmModule } from "@nestjs/typeorm";
import type { Environment } from "../config/env";
import { databaseOptions } from "./database.options";
@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<Environment, true>) =>
        databaseOptions({
          DB_HOST: config.get("DB_HOST", { infer: true }),
          DB_PORT: config.get("DB_PORT", { infer: true }),
          DB_USERNAME: config.get("DB_USERNAME", { infer: true }),
          DB_PASSWORD: config.get("DB_PASSWORD", { infer: true }),
          DB_DATABASE: config.get("DB_DATABASE", { infer: true }),
          DB_SSL: config.get("DB_SSL", { infer: true }),
          DB_LOGGING: config.get("DB_LOGGING", { infer: true }),
        }),
    }),
  ],
})
export class DatabaseModule {}
