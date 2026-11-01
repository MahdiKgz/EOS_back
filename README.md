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

## مدل هویت و نقش‌ها

مدل کاربر از `track_firewall_log/backend/prisma/schema.prisma` اقتباس شده و شامل `username`، `displayName`، ایمیل و تلفن اختیاری، هش رمز، وضعیت فعال، دسترسی‌ها و زمان‌ها است. نقش‌های قبلی با یک فیلد `role` جایگزین شده‌اند:

- `pl_admin`: ادمین سامانه
- `co_admin`: ادمین شرکت
- `co_employee`: کارمند شرکت

فیلد جداگانه `platformRole` استفاده نمی‌شود. پیش‌فرض مدل فعلاً کمترین سطح نقش (`co_employee`) است و ثبت‌نام عمومی امکان تعیین نقش ندارد. تخصیص نقش و جریان اختصاصی هر نقش پس از مشخص شدن flowها تکمیل می‌شود؛ نقش به‌تنهایی هنوز مجوز عملیات شرکت ایجاد نمی‌کند.

احراز هویت JWT با نشست‌های قابل لغو و اتصال RTK Query فرانت آماده است. فرانت مسیر داشبورد را با بررسی نشست محافظت می‌کند. تخصیص دسترسی‌های دامنه و جریان اختصاصی نقش‌ها جداگانه تکمیل می‌شوند. اجرای برنامه به `JWT_SECRET` با حداقل ۳۲ کاراکتر در محیط نیاز دارد. مسیر بازیابی نیز به تنظیم SMTP نیاز دارد.

## API احراز هویت

| مسیر زیر `/api/v1/auth` | روش  | کاربرد                                        |
| ----------------------- | ---- | --------------------------------------------- |
| `/register`             | POST | ایجاد کاربر با نقش co_employee و صدور JWT     |
| `/login`                | POST | ورود با username و password                   |
| `/me`                   | GET  | هویت حساب با Bearer JWT معتبر                 |
| `/logout`               | POST | ابطال نشست جاری                               |
| `/forget-password`      | POST | دریافت لینک بازیابی از طریق email             |
| `/reset-password`       | POST | تغییر رمز با token یک‌بارمصرف و password جدید |

JWT فقط با HS256، issuer=`eosnet` و audience=`eosnet-web` پذیرفته می‌شود. انقضا با `JWT_TTL_SECONDS` (پیش‌فرض ۳۶۰۰ ثانیه) تعیین می‌شود. هش توکن در نشست نگه‌داری می‌شود و خروج، نشست را از دسترس خارج می‌کند. تمام مسیرها به‌صورت پیش‌فرض نیاز به احراز هویت دارند و مسیرهای عمومی صریحاً علامت‌گذاری شده‌اند. محدودیت تلاش برای ورود، ثبت‌نام و بازیابی اعمال می‌شود.

رمز با bcrypt و cost=12 ذخیره می‌شود. حداقل طول مطابق نسخه مبنا ۱۲ کاراکتر است؛ رمزهای رایج و رمز شامل نام کاربری رد می‌شوند. برای جلوگیری از کوتاه‌شدن خاموش bcrypt، طول UTF-8 بیشتر از ۷۲ بایت هم رد می‌شود. passwordHash و tokenHash در پاسخ کاربر برگردانده نمی‌شوند.

برای ارسال واقعی لینک بازیابی، `SMTP_HOST`، `SMTP_PORT`، `SMTP_SECURE` و `SMTP_FROM` را تنظیم کنید؛ در صورت نیاز `SMTP_USERNAME` و `SMTP_PASSWORD` را هم قرار دهید. `APP_URL` آدرس معتبر فرانت برای تولید لینک است. لینک ۳۰ دقیقه اعتبار دارد، در دیتابیس فقط هش آن ذخیره می‌شود و پس از مصرف قابل استفاده مجدد نیست. تغییر رمز همه نشست‌های قبلی را لغو می‌کند. در نبود SMTP، مسیر بازیابی 503 می‌دهد و ادعای ارسال ایمیل نمی‌کند.

```bash
pnpm test:auth
```

این تست build و API واقعی را با یک SMTP محلی آزمایشی اجرا می‌کند؛ ورود، JWT جعلی و منقضی، محدودیت نقش، خروج، بازیابی یک‌بارمصرف و ابطال نشست را می‌آزماید. دیتابیس باید بالا باشد؛ تنها کاربر موقت همان تست پاک می‌شود. هیچ ایمیلی به سرویس خارجی ارسال نمی‌شود.

## Code formatting

- `pnpm format`: format the project with Prettier.
- `pnpm format:check`: check formatting without changing files.
- Husky runs `lint-staged` before every commit to format staged files and include the changes in the commit. A formatting failure blocks the commit.
- `pnpm install` activates the hooks through the `prepare` script.
