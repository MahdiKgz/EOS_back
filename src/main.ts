import { DeviceMonitoringWorker } from "./modules/devices/device-monitoring.worker";
import "reflect-metadata";
import { Logger, ValidationPipe } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import type { NestExpressApplication } from "@nestjs/platform-express";
import type { Environment } from "./config/env";
async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  app.useBodyParser("raw", { type: "application/octet-stream", limit: 20 * 1024 * 1024 });
  const config = app.get(ConfigService<Environment, true>);
  app.setGlobalPrefix("api/v1");
  app.enableCors({ origin: config.get("CORS_ORIGINS", { infer: true }) });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  app.enableShutdownHooks();
  await app.listen(config.get("PORT", { infer: true }));
  app.get(DeviceMonitoringWorker).start();
}
bootstrap().catch((error: unknown) => {
  Logger.error(error);
  process.exitCode = 1;
});
