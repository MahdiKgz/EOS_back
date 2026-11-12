import type { DeviceType } from "./device.entity";
export const vendorKeys = [
  "linux",
  "mikrotik",
  "fortigate",
  "cisco",
  "sophos",
  "esxi",
  "pfsense",
] as const;
export type VendorKey = (typeof vendorKeys)[number];
export const supportStates = ["implemented", "partial", "planned", "unsupported"] as const;
export type SupportState = (typeof supportStates)[number];
type Capability = {
  key: string;
  title: string;
  mode: "read" | "mutate";
  state: SupportState;
  description: string;
};
type Platform = { key: string; title: string; state: SupportState; description: string };
export type VendorDefinition = {
  key: VendorKey;
  title: string;
  description: string;
  state: SupportState;
  requirements: string[];
  platforms: Platform[];
  capabilities: Capability[];
  registration: {
    type: DeviceType;
    vendor: string;
    protocol: "ssh" | "api";
    managementPort: number;
  };
};
const cap = (
  key: string,
  title: string,
  mode: Capability["mode"],
  state: SupportState,
  description: string,
): Capability => ({ key, title, mode, state, description });
const platform = (
  key: string,
  title: string,
  state: SupportState,
  description: string,
): Platform => ({ key, title, state, description });
const sshRequirement = "حساب SSH با مجوز خواندن و کلید عمومی معتبر میزبان لازم است.";
const baseRead = cap(
  "ssh.read",
  "ورود و فرمان‌های خواندنی SSH",
  "read",
  "implemented",
  "تأیید هویت و فرمان‌های مشخص شبکه و عیب‌یابی از جزئیات تجهیز در دسترس‌اند.",
);
const backup = cap(
  "backup.restore",
  "بک‌آپ و بازیابی تنظیمات",
  "mutate",
  "implemented",
  "دریافت، بررسی فایل، پیش‌نمایش و تأیید بازیابی مطابق روش پشتیبانی‌شدهٔ همین وندور.",
);
const monitor = cap(
  "monitoring",
  "پایش و نمودار منابع",
  "read",
  "implemented",
  "پایش دستی و دوره‌ای؛ فقط شاخص‌های دریافت‌شده از اتصال واقعی نمایش داده می‌شوند.",
);
export const vendorCatalog: VendorDefinition[] = [
  {
    key: "linux",
    title: "Linux",
    description: "سرورهای لینوکسی با اتصال SSH، پایش منابع، ترمینال و بک‌آپ.",
    state: "partial",
    registration: { type: "linux_edge", vendor: "linux", protocol: "ssh", managementPort: 22 },
    requirements: [
      sshRequirement,
      "خواندن /proc و اطلاعات شبکه و فایل‌سیستم؛ مجوز مسیرهای انتخاب‌شده برای بک‌آپ لازم است.",
    ],
    platforms: [
      platform(
        "linux",
        "Linux",
        "partial",
        "میزبان باید Linux باشد؛ عملیات فایل بر اساس سطح دسترسی حساب انجام می‌شود.",
      ),
    ],
    capabilities: [
      baseRead,
      monitor,
      cap(
        "terminal",
        "ترمینال تعاملی",
        "mutate",
        "implemented",
        "نشست اختصاصی با تأیید مقصد، محدودیت عمر و ممیزی شروع/پایان.",
      ),
      backup,
      cap(
        "linux.data-backup",
        "بک‌آپ فایل و دیتابیس با مقصد SFTP",
        "mutate",
        "planned",
        "انتخاب کامل محتوا، دیتابیس و زمان‌بندی اختصاصی هنوز در حال انتقال است.",
      ),
    ],
  },
  {
    key: "mikrotik",
    title: "MikroTik",
    description: "تجهیزات RouterOS با اتصال SSH یا REST امن، موجودی شبکه و بک‌آپ تنظیمات.",
    state: "partial",
    registration: { type: "mikrotik", vendor: "mikrotik", protocol: "ssh", managementPort: 22 },
    requirements: [
      sshRequirement,
      "REST به RouterOS 7، سرویس HTTPS و مجوز rest-api/read نیاز دارد.",
    ],
    platforms: [
      platform(
        "routeros-7",
        "RouterOS 7",
        "partial",
        "موجودی REST و روش‌های SSH پشتیبانی می‌شوند.",
      ),
      platform(
        "routeros-6",
        "RouterOS 6",
        "partial",
        "REST در دسترس نیست؛ قابلیت‌های SSH به نسخه و مجوز حساب وابسته‌اند.",
      ),
    ],
    capabilities: [
      baseRead,
      monitor,
      cap(
        "rest.inventory",
        "موجودی REST",
        "read",
        "implemented",
        "هویت، منابع، رابط‌ها، IP و مسیر، فایروال، سرویس‌ها و شمارنده‌های ترافیک.",
      ),
      backup,
      cap(
        "mikrotik.network-change",
        "تغییرات کنترل‌شدهٔ شبکه و VPN",
        "mutate",
        "planned",
        "عملیات و جریان‌های تأیید مبنا هنوز به‌طور کامل منتقل نشده‌اند.",
      ),
    ],
  },
  {
    key: "fortigate",
    title: "FortiGate",
    description: "فایروال FortiOS با SSH، بررسی وضعیت و بک‌آپ تنظیمات.",
    state: "partial",
    registration: { type: "fortigate", vendor: "fortinet", protocol: "ssh", managementPort: 22 },
    requirements: [
      sshRequirement,
      "حساب باید مجوز CLIهای خواندنی و برای بازیابی، مجوز جداگانهٔ عملیات تنظیمات داشته باشد.",
    ],
    platforms: [
      platform(
        "fortios",
        "FortiOS",
        "partial",
        "هویت FortiGate پیش از عملیات اختصاصی بررسی می‌شود.",
      ),
    ],
    capabilities: [
      baseRead,
      cap(
        "fortigate.health",
        "موجودی و سلامت FortiOS",
        "read",
        "partial",
        "هویت، سلامت، رابط‌ها، policy/NAT، VPN، HA/VDOM و اشیای شبکه از SSH با وضعیت مستقل فرمان‌ها دریافت می‌شوند.",
      ),
      backup,
      cap(
        "fortigate.interfaces",
        "کنترل رابط و VLAN",
        "mutate",
        "implemented",
        "alias، نقش، وضعیت، IPv4/mask، دسترسی مدیریتی و ساخت VLAN با پیش‌نمایش، یک تأیید، خواندن نتیجه و ممیزی؛ بدون بازنویسی VLAN موجود.",
      ),
      cap(
        "fortigate.objects",
        "آدرس، سرویس، گروه، زمان‌بندی، Zone و NAT",
        "mutate",
        "implemented",
        "۲۶ عملیات شامل VIP، گروه VIP و مخزن IP با پیش‌نمایش، وابستگی زنده، یک تأیید و خواندن نتیجه؛ حذف آدرس/سرویس/Zone به اشیای مدیریت‌شده محدود است.",
      ),
      cap(
        "fortigate.policy",
        "مدیریت Policy",
        "mutate",
        "implemented",
        "ساخت عمومی/خروجی/مسدودسازی/DNAT/Zone، ویرایش، وضعیت، ترتیب، توضیح و حذف مدیریت‌شده؛ شناسهٔ خودکار با نشانگر همان اجرا و خواندن نتیجه تطبیق داده می‌شود.",
      ),
      cap(
        "fortigate.network",
        "Central SNAT، مسیر ثابت، DNS و NTP",
        "mutate",
        "implemented",
        "ساخت SNAT با مرجع آدرس و نمایش حالت NAT، ساخت/ویرایش/حذف مسیر با شناسهٔ واقعی، DNS عمومی و NTP سفارشی با پیش‌نمایش و خواندن نتیجه؛ بدون تغییر خودکار حالت NAT.",
      ),
      cap(
        "fortigate.admin",
        "مدیریت حساب و دسترسی",
        "mutate",
        "partial",
        "ساخت حساب محلی با گذرواژهٔ مخزن شخصی، trusthost، حذف، پیکربندی حساب API بدون تولید کلید و تنظیم پورت HTTPS/سرویس بومی؛ غیرفعال‌سازی روش‌های ورود فقط FortiOS ۸ به بالا، با خواندن نسخه و نتیجهٔ واقعی.",
      ),
      cap(
        "fortigate.cluster",
        "تنظیم HA و SD-WAN",
        "mutate",
        "implemented",
        "حالت/گروه و Priority عمومی HA با پیش‌بررسی وضعیت؛ ساخت Zone، عضو، بررسی ping و قانون دستی SD-WAN در VDOM با شناسهٔ واقعی و خواندن نتیجه. ذخیرهٔ تنظیم به معنی اثبات سلامت کلاستر یا مسیر نیست.",
      ),
      cap(
        "fortigate.vdom",
        "مدیریت VDOM و انتقال رابط",
        "mutate",
        "implemented",
        "ساخت با پشتیبانی از تأیید بومی CLI، ویرایش واقعی نام کوتاه/توضیح، انتقال رابط به مقصد موجود و حذف با کنترل مرجع‌های دستگاه؛ محدودهٔ عمومی و خواندن نتیجه از نشست تازه، بدون تغییر خودکار حالت VDOM یا حذف وابستگی‌ها.",
      ),
      cap(
        "fortigate.policy-change",
        "مدیریت پیشرفته و VPN",
        "mutate",
        "planned",
        "اجرای این عملیات از کاتالوگ فعال نشده است.",
      ),
    ],
  },
  {
    key: "cisco",
    title: "Cisco",
    description: "تجهیزات IOS و IOS-XE؛ کشف خانواده، موجودی و سلامت خواندنی و بک‌آپ تنظیمات.",
    state: "partial",
    registration: { type: "cisco", vendor: "cisco", protocol: "ssh", managementPort: 22 },
    requirements: [
      sshRequirement,
      "دسترسی EXEC و مجوز فرمان‌های لازم؛ خانواده‌های NX-OS، IOS-XR، ASA و FTD با مسیر IOS اجرا نمی‌شوند.",
    ],
    platforms: [
      platform(
        "cisco-ios-xe",
        "Cisco IOS-XE",
        "partial",
        "خانواده و موجودی از SSH دریافت می‌شوند؛ نتیجه و مجوز هر فرمان جداگانه نمایش داده می‌شود.",
      ),
      platform(
        "cisco-ios-classic",
        "Cisco IOS Classic",
        "partial",
        "روش‌های مشترک IOS فقط در صورت تأیید هویت و مجوز حساب اجرا می‌شوند.",
      ),
      ...[
        ["nx-os", "NX-OS"],
        ["ios-xr", "IOS-XR"],
        ["asa", "ASA"],
        ["ftd", "FTD"],
      ].map(([key, title]) =>
        platform(
          "cisco-" + key,
          "Cisco " + title,
          "planned",
          "این خانواده برای اجرای کانکتور IOS فعال نشده است.",
        ),
      ),
      platform(
        "cisco-unknown",
        "خانوادهٔ نامشخص",
        "unsupported",
        "وجود نام Cisco در مشخصات به معنی تأیید خانوادهٔ سیستم‌عامل نیست.",
      ),
    ],
    capabilities: [
      baseRead,
      cap(
        "cisco.health",
        "سلامت CPU، حافظه و ذخیره‌ساز",
        "read",
        "implemented",
        "خروجی واقعی فرمان‌های خواندنی؛ فرمان ناموفق و دادهٔ ناموجود جداگانه مشخص می‌شوند.",
      ),
      backup,
      ...[
        ["inventory", "موجودی سخت‌افزار"],
        ["interfaces", "وضعیت و شمارندهٔ رابط‌ها"],
        ["vlans", "فهرست VLAN و Trunk"],
        ["routing", "مسیریابی و همسایه‌ها"],
        ["acl", "فهرست‌های کنترل دسترسی"],
      ].map(([key, title]) =>
        cap(
          "cisco." + key,
          title,
          "read",
          "implemented",
          "از فرمان‌های ثابت خواندنی دریافت می‌شود؛ نسخه، سطح دسترسی و نتیجهٔ هر فرمان در گزارش تجهیز مشخص است.",
        ),
      ),
      cap(
        "cisco.vlan-create",
        "ساخت VLAN و EtherChannel",
        "mutate",
        "planned",
        "در مبنا نیز عملیات برنامه‌ریزی‌شده است و اجرایی نیست.",
      ),
    ],
  },
  {
    key: "sophos",
    title: "Sophos Firewall",
    description: "موجودی فایروال از XML API روی HTTPS؛ شاخص‌های موجود و تنظیمات خواندنی.",
    state: "partial",
    registration: {
      type: "generic_firewall",
      vendor: "sophos",
      protocol: "api",
      managementPort: 4444,
    },
    requirements: [
      "XML API را فعال و IP سرور سامانه را در میزبان‌های مجاز قرار دهید.",
      "اعتبارنامهٔ API و گواهی معتبر یا اثر انگشت کامل SHA-256 لازم است.",
    ],
    platforms: [
      platform(
        "sophos-firewall",
        "Sophos Firewall",
        "partial",
        "سطح دسترسی هر ماژول جداگانه بررسی می‌شود؛ تنظیم VPN به معنی فعال بودن تونل نیست.",
      ),
    ],
    capabilities: [
      cap(
        "sophos.inventory",
        "موجودی XML API",
        "read",
        "implemented",
        "رابط، Zone، Gateway، قوانین، IP Host، Service و تنظیمات VPN از ماژول‌های خواندنی دریافت می‌شوند.",
      ),
      cap(
        "sophos.monitoring",
        "پایش رابط‌ها",
        "read",
        "partial",
        "وضعیت رابط‌های دریافت‌شده قابل پایش است؛ شاخص ناموجود ساخته نمی‌شود.",
      ),
      cap(
        "sophos.configuration",
        "تغییرات کنترل‌شدهٔ فایروال و VPN",
        "mutate",
        "planned",
        "عملیات تغییردهندهٔ مبنا هنوز در حال انتقال است.",
      ),
    ],
  },
  {
    key: "esxi",
    title: "VMware ESXi",
    description: "هاست مستقل ESXi با SOAP API یا SSH؛ موجودی، منابع و نمودارها.",
    state: "partial",
    registration: { type: "esxi", vendor: "vmware", protocol: "api", managementPort: 443 },
    requirements: [
      "SOAP به هاست مستقل ESXi و گواهی قابل اعتماد نیاز دارد؛ vCenter در این مسیر پشتیبانی نمی‌شود.",
      sshRequirement,
    ],
    platforms: [
      platform(
        "esxi-standalone",
        "ESXi مستقل",
        "partial",
        "موجودی SOAP و SSH خواندنی در دسترس‌اند؛ عملیات هاست و VM به‌طور کامل منتقل نشده‌اند.",
      ),
      platform("vcenter", "vCenter", "unsupported", "این اتصال فقط هاست مستقل را می‌پذیرد."),
    ],
    capabilities: [
      cap(
        "esxi.inventory",
        "موجودی SOAP و SSH",
        "read",
        "implemented",
        "هویت، منابع، دیتاستور، شبکه، DNS/NTP و سرویس‌ها؛ داده‌های VM و سنسور کامل از API دریافت می‌شوند.",
      ),
      monitor,
      cap(
        "esxi.host-change",
        "عملیات کنترل‌شدهٔ هاست",
        "mutate",
        "planned",
        "پیش‌نمایش و تأیید عملیات هاست هنوز در حال انتقال است.",
      ),
      cap(
        "esxi.vm-backup",
        "بک‌آپ و بازیابی VM",
        "mutate",
        "planned",
        "انتخاب VM/دیتاستور، انتقال و بررسی صحت هنوز منتقل نشده‌اند.",
      ),
    ],
  },
  {
    key: "pfsense",
    title: "pfSense",
    description: "ثبت موجودی و اتصال اولیهٔ SSH؛ عملیات اختصاصی این پلتفرم محدود است.",
    state: "partial",
    registration: { type: "pfsense", vendor: "netgate", protocol: "ssh", managementPort: 22 },
    requirements: [
      sshRequirement,
      "هدف باید FreeBSD و محصول pfSense باشد؛ مجوز پوسته و فرمان‌های خواندنی لازم است.",
    ],
    platforms: [
      platform(
        "pfsense",
        "pfSense",
        "partial",
        "مسیر پایهٔ SSH موجود است؛ اجرای تغییرات API در مبنا برنامه‌ریزی‌شده است.",
      ),
    ],
    capabilities: [
      baseRead,
      cap(
        "pfsense.snmp",
        "شاخص‌های SNMPv3",
        "read",
        "partial",
        "با کانال SNMPv3 تأییدشده، فقط OIDهای پشتیبانی‌شده دریافت می‌شوند.",
      ),
      cap(
        "pfsense.change",
        "تغییرات API و فایروال",
        "mutate",
        "planned",
        "در مبنا مسیر برنامه‌ریزی‌شده است و اجرا فعال نیست.",
      ),
    ],
  },
];
