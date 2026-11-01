import "reflect-metadata";
import "dotenv/config";
import { DataSource } from "typeorm";
import { validateEnv } from "../config/env";
import { databaseOptions } from "./database.options";
export default new DataSource(databaseOptions(validateEnv(process.env)));
