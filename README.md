# EOSNet Backend

NestJS 11 + TypeScript + TypeORM 0.3 + PostgreSQL 17.

## اجرا

پیش‌نیاز: Node.js 22 یا جدیدتر، pnpm 10.26.1 و Docker Compose.

```bash
cp .env.example .env
pnpm install
pnpm db:up
pnpm start:dev
```

API روی `http://localhost:4000/api/v1` اجرا می‌شود. مسیر `GET /api/v1/health` با اجرای `SELECT 1` اتصال واقعی دیتابیس را بررسی می‌کند؛ پاسخ موفق `{"status":"ok","database":"up"}` است و در خطای دیتابیس پاسخ 503 می‌دهد.

PostgreSQL فقط روی loopback و پورت پیش‌فرض 5433 منتشر می‌شود. داده‌ها در volume پایدار `postgres_data` نگهداری می‌شوند. `pnpm db:down` کانتینر را متوقف می‌کند و داده را نگه می‌دارد. تغییر credential در `.env` اعتبارهای volume موجود را تغییر نمی‌دهد.

## تنظیمات

متغیرهای ضروری و پیش‌فرض‌ها در `.env.example` هستند. برنامه و CLI migration از یک تنظیم مشترک استفاده می‌کنند و در صورت تنظیم نامعتبر متوقف می‌شوند.

- `PORT`: پورت API، پیش‌فرض 4000.
- `CORS_ORIGINS`: originهای مجاز فرانت با جداکننده کاما.
- `DB_HOST`, `DB_PORT`, `DB_USERNAME`, `DB_PASSWORD`, `DB_DATABASE`: مشخصات PostgreSQL.
- `DB_SSL`: برای اتصال TLS با اعتبارسنجی گواهی، `true`؛ پیش‌فرض `false` برای Docker محلی.
- `DB_LOGGING`: فعال‌سازی log کوئری‌ها با `true`.

مقادیر نمونه برای توسعه محلی‌اند؛ در محیط استقرار credential مناسب تزریق کنید. فایل `.env` از Git کنار گذاشته شده است.

## ساختار

```text
src/
  config/                  اعتبارسنجی محیط
  database/
    database.module.ts     اتصال TypeORM در Nest
    database.options.ts    تنظیمات مشترک برنامه و migration
    data-source.ts         ورودی TypeORM CLI
    migrations/            migrationهای schema
  modules/
    health/                بررسی سلامت دیتابیس
  app.module.ts
  main.ts                  prefix، CORS و ValidationPipe
```

ماژول‌های دامنه را زیر `src/modules/<domain>` اضافه کنید. entityها با پسوند `.entity.ts` شناسایی می‌شوند. `TypeOrmModule.forFeature([Entity])` را در ماژول مصرف‌کننده ثبت کنید. DTOها با class-validator و ValidationPipe سراسری اعتبارسنجی می‌شوند.

## Migration

`synchronize` و اجرای خودکار migration خاموش هستند. هنوز entity تجاری تعریف نشده و migration اولیه لازم نیست. پس از افزودن entity:

```bash
pnpm migration:generate src/database/migrations/DescribeChange
pnpm migration:run
pnpm migration:revert
```

برای migration دستی:

```bash
pnpm migration:create src/database/migrations/DescribeChange
```

## بررسی و اجرای build

```bash
pnpm lint
pnpm typecheck
pnpm build
pnpm migration:run:prod
pnpm start:prod
```

قبل از migration در محیط عملیاتی، تغییرات SQL را بازبینی کنید. مسیرهای entity و migration برای اجرای TypeScript و JavaScript کامپایل‌شده آماده‌اند.

منابع: [NestJS / TypeORM](https://docs.nestjs.com/techniques/database)، [TypeORM migrations](https://typeorm.io/docs/migrations/setup/).
