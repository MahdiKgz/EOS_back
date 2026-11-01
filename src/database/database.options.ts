import { join } from "node:path";
import type { DataSourceOptions } from "typeorm";
import type { Environment } from "../config/env";
export function databaseOptions(
  env: Pick<
    Environment,
    "DB_HOST" | "DB_PORT" | "DB_USERNAME" | "DB_PASSWORD" | "DB_DATABASE" | "DB_SSL" | "DB_LOGGING"
  >,
): DataSourceOptions {
  return {
    type: "postgres",
    host: env.DB_HOST,
    port: env.DB_PORT,
    username: env.DB_USERNAME,
    password: env.DB_PASSWORD,
    database: env.DB_DATABASE,
    ssl: env.DB_SSL ? { rejectUnauthorized: true } : false,
    logging: env.DB_LOGGING,
    entities: [join(__dirname, "..", "**", "*.entity.{ts,js}")],
    migrations: [join(__dirname, "migrations", "*.{ts,js}")],
    synchronize: false,
    migrationsRun: false,
  };
}
