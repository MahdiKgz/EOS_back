import "reflect-metadata";
import { Logger, ValidationPipe } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import type { Environment } from "./config/env";
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
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
}
bootstrap().catch((error: unknown) => {
  Logger.error(error);
  process.exitCode = 1;
});
