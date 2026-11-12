import { isIP } from "node:net";
import type { FortiCollection, FortiCommandId, FortiTable } from "./fortigate-inventory";
export type FortiCheckStatus =
  "safe" | "needs_review" | "critical" | "not_checked" | "not_supported";
export type FortiFinding = {
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  evidence: string;
  recommendedAction: string;
};
export type FortiCheckSection = {
  key: string;
  title: string;
  status: FortiCheckStatus;
  coverage: "complete" | "partial" | "unavailable";
  sources: FortiCommandId[];
  summary: string;
  evidence: { label: string; value: string }[];
  findings: FortiFinding[];
};
const finding = (
  title: string,
  severity: FortiFinding["severity"],
  evidence: string,
  recommendedAction: string,
): FortiFinding => ({ title, severity, evidence, recommendedAction });
export function buildFortiDailyCheck(collection: FortiCollection) {
  const { system, health, commandEvidence } = collection,
    table = (key: string) => collection.tables.find((t) => t.key === key),
    rows = (key: string) => table(key)?.rows ?? [],
    raw = (key: string) =>
      collection.rawSections.find((s) => s.key === key)?.lines.join("\n") ?? "";
  const sections: FortiCheckSection[] = [];
  function add(
    key: string,
    title: string,
    sources: FortiCommandId[],
    hasEvidence: boolean,
    evidence: FortiCheckSection["evidence"],
    findings: FortiFinding[],
    parsed = true,
  ) {
    const states = sources.map(
        (source) => commandEvidence.find((e) => e.commandId === source)?.state ?? "not_collected",
      ),
      full = states.every((state) => state === "collected") && parsed && hasEvidence,
      any = states.some((s) => s === "collected" || s === "partial") && hasEvidence;
    const status: FortiCheckStatus = findings.some((f) => f.severity === "critical")
      ? "critical"
      : findings.some((f) => f.severity === "high" || f.severity === "medium")
        ? "needs_review"
        : full
          ? "safe"
          : states.every((s) => s === "not_supported")
            ? "not_supported"
            : "not_checked";
    sections.push({
      key,
      title,
      status,
      coverage: full ? "complete" : any ? "partial" : "unavailable",
      sources,
      evidence,
      findings,
      summary:
        status === "safe"
          ? "در شواهد کامل این بخش، یافتهٔ مهمی مشاهده نشد."
          : status === "not_checked"
            ? "دادهٔ کافی برای نتیجه‌گیری این بخش در دسترس نیست."
            : status === "not_supported"
              ? "فرمان‌های این بخش در نسخه یا سطح دسترسی فعلی پشتیبانی نشدند."
              : `${findings.length} یافته بر اساس خروجی دریافت‌شده نیازمند بررسی است.`,
    });
  }
  const resourceFindings: FortiFinding[] = [];
  for (const [name, value] of [
    ["CPU", health.cpuUsagePercent],
    ["حافظه", health.memoryUsagePercent],
  ] as const)
    if (value !== null && value >= 80)
      resourceFindings.push(
        finding(
          `مصرف بالای ${name}`,
          value >= 90 ? "critical" : "medium",
          `${value}%`,
          "روند منابع و پردازش‌های پرمصرف را بررسی کنید.",
        ),
      );
  add(
    "system_health",
    "سلامت سیستم",
    ["system", "performance"],
    health.cpuUsagePercent !== null || health.memoryUsagePercent !== null,
    [
      {
        label: "CPU",
        value: health.cpuUsagePercent === null ? "نامشخص" : `${health.cpuUsagePercent}%`,
      },
      {
        label: "حافظه",
        value: health.memoryUsagePercent === null ? "نامشخص" : `${health.memoryUsagePercent}%`,
      },
      {
        label: "نشست‌ها",
        value: health.sessionCount === null ? "نامشخص" : String(health.sessionCount),
      },
    ],
    resourceFindings,
    health.cpuUsagePercent !== null && health.memoryUsagePercent !== null,
  );
  const license = system.license,
    licenseFindings =
      license && /\b(?:invalid|expired|unlicensed)\b|not (?:licensed|valid)/i.test(license)
        ? [
            finding(
              "وضعیت مجوز نیازمند بررسی است",
              "medium",
              license,
              "وضعیت مجوز و سرویس‌های FortiGuard را بررسی کنید؛ مجوز نامعتبر در محیط آزمایشگاهی به‌تنهایی خرابی فایروال را اثبات نمی‌کند.",
            ),
          ]
        : [];
  add(
    "license",
    "مجوز و FortiGuard",
    ["system", "fortiguard"],
    !!license,
    [{ label: "وضعیت مجوز", value: license ?? "نامشخص" }],
    licenseFindings,
    !!license &&
      /^(?:valid|invalid|expired|licensed|unlicensed|not (?:licensed|valid))\b/i.test(license),
  );
  const interfaceFindings: FortiFinding[] = [];
  for (const row of rows("interfaces")) {
    const access = String(row.allowaccess ?? "").split(/[,\s]+/),
      name = String(row.name);
    if (
      (row.role === "wan" || /^(?:wan\d*|external|public)$/i.test(name)) &&
      access.some((a) => ["https", "http", "ssh", "telnet"].includes(a))
    )
      interfaceFindings.push(
        finding(
          `دسترسی مدیریتی روی ${name}`,
          "high",
          access.join(", "),
          "allowaccess و محدودیت مبدا را متناسب با شبکهٔ مدیریت بررسی کنید. این مشاهده به‌تنهایی دسترسی از اینترنت را اثبات نمی‌کند.",
        ),
      );
    if (access.some((a) => a === "http" || a === "telnet"))
      interfaceFindings.push(
        finding(
          `پروتکل مدیریتی ناامن روی ${name}`,
          "high",
          access.join(", "),
          "استفاده از HTTPS/SSH و محدودیت مبدا را بررسی کنید.",
        ),
      );
  }
  const down = rows("physical").filter((row) => row.status === "down");
  for (const row of down)
    interfaceFindings.push(
      finding(
        `لینک ${row.name} قطع است`,
        "low",
        "physical status=down",
        "کاربری رابط و اتصال فیزیکی را بررسی کنید؛ قطع بودن می‌تواند عمدی باشد.",
      ),
    );
  add(
    "interfaces",
    "رابط‌ها و دسترسی مدیریت",
    ["interfaces", "physical"],
    rows("interfaces").length > 0,
    [
      { label: "رابط‌های ثبت‌شده", value: String(rows("interfaces").length) },
      {
        label: "لینک قطع مشاهده‌شده",
        value: table("physical")?.state === "collected" ? String(down.length) : "نامشخص",
      },
    ],
    interfaceFindings,
    rows("physical").some((r) => r.status === "up" || r.status === "down"),
  );
  const routeText = raw("routes"),
    dnsText = raw("dns"),
    defaultRoute = routeText
      .split("\n")
      .find((line) => /(?:^|\s)(?:0\.0\.0\.0\/0|::\/0)(?:\s|$)/.test(line)),
    dns = [...dnsText.matchAll(/^\s*(?:primary|secondary)\s*:\s*(\S+)/gim)]
      .map((m) => m[1])
      .filter((ip) => !!isIP(ip));
  const routeObserved = /\b(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}\b|::\/\d+/.test(routeText),
    routeFindings: FortiFinding[] = [];
  if (routeObserved && !defaultRoute)
    routeFindings.push(
      finding(
        "مسیر پیش‌فرض مشاهده نشد",
        "medium",
        "routing table has routes, no default route",
        "نیاز این تجهیز به مسیر پیش‌فرض و مقصد gateway را بررسی کنید.",
      ),
    );
  add(
    "route_dns",
    "مسیریابی و DNS",
    ["routes", "dns"],
    routeObserved || dns.length > 0,
    [
      { label: "مسیر پیش‌فرض", value: defaultRoute ?? "مشاهده نشد/نامشخص" },
      { label: "DNS", value: dns.join(", ") || "نامشخص" },
    ],
    routeFindings,
    routeObserved && dns.length > 0,
  );
  const policyFindings: FortiFinding[] = [];
  for (const policy of rows("policies"))
    if (
      policy.status !== "disable" &&
      policy.action === "accept" &&
      policy.logtraffic === "disable"
    )
      policyFindings.push(
        finding(
          `ثبت لاگ policy ${policy.id} غیرفعال است`,
          "medium",
          String(policy.name ?? policy.id),
          "تنظیم logtraffic را مطابق سیاست نگه‌داری لاگ بررسی کنید.",
        ),
      );
  const policyTables = ["policies", "vips", "ipPools"]
    .map(table)
    .filter((t): t is FortiTable => !!t);
  add(
    "policy_nat_vip",
    "Policy، NAT و VIP",
    ["policies", "vips", "ipPools"],
    rows("policies").length > 0,
    [
      { label: "Policy", value: String(rows("policies").length) },
      { label: "VIP", value: String(rows("vips").length) },
      { label: "IP Pool", value: String(rows("ipPools").length) },
    ],
    policyFindings,
    policyTables.every((t) => t.state === "collected") &&
      rows("policies").every(
        (row) =>
          row.status === "disable" ||
          (row.action !== null && (row.action !== "accept" || row.logtraffic !== null)),
      ),
  );
  const vpnFindings: FortiFinding[] = [];
  for (const tunnel of rows("vpn"))
    if (tunnel.status === "down")
      vpnFindings.push(
        finding(
          `تونل ${tunnel.name} فعال نیست`,
          "medium",
          "selectors up=0 / observed status=down",
          "peer، مسیر و Phase 1/2 را بررسی کنید.",
        ),
      );
  const vpnRows = rows("vpn"),
    ssl = raw("sslSettings"),
    sslState = /^\s*set\s+status\s+disable\s*$/m.test(ssl)
      ? "غیرفعال"
      : /^\s*set\s+status\s+enable\s*$/m.test(ssl)
        ? "فعال"
        : "نامشخص",
    sslUsers = raw("sslMonitor").match(/(?:users?|user count)\s*[:=]\s*(\d+)/i)?.[1] ?? null;
  if (
    sslState === "فعال" &&
    !/(?:source-interface|source-address|user-group|set groups|servercert)/i.test(ssl)
  )
    vpnFindings.push(
      finding(
        "شواهد محدودسازی SSL-VPN کافی نیست",
        "medium",
        "SSL-VPN explicitly enabled; restriction/certificate not observed",
        "گواهی، گروه کاربری و محدودیت مبدا را بررسی کنید.",
      ),
    );
  add(
    "vpn",
    "IPsec و SSL-VPN",
    ["phase1", "phase2", "ipsecSummary", "ipsecStatus", "sslSettings", "sslMonitor"],
    vpnRows.length > 0 || sslUsers !== null || sslState !== "نامشخص",
    [
      { label: "تونل‌های مشاهده‌شده", value: String(vpnRows.length) },
      { label: "SSL-VPN", value: sslState },
      { label: "کاربران فعال SSL-VPN", value: sslUsers ?? "نامشخص" },
    ],
    vpnFindings,
    !vpnRows.some((row) => row.status === "unknown") && sslState !== "نامشخص" && sslUsers !== null,
  );
  const ha = raw("ha"),
    haMode = ha.match(/^Mode:\s*(.+)$/im)?.[1] ?? system.haMode,
    haFindings: FortiFinding[] = [];
  if (/out.of.sync|not synchronized|not in.sync/i.test(ha))
    haFindings.push(
      finding(
        "HA همگام نیست",
        "high",
        "out-of-sync",
        "وضعیت اعضا، heartbeat و اختلاف پیکربندی را بررسی کنید.",
      ),
    );
  add(
    "ha_vdom_zone",
    "HA، VDOM و Zone",
    ["ha", "haConfig", "vdoms", "zones"],
    !!haMode,
    [
      { label: "HA", value: haMode ?? "نامشخص" },
      { label: "VDOM", value: String(rows("vdoms").length) },
      { label: "Zone", value: String(rows("zones").length) },
    ],
    haFindings,
  );
  const admins = rows("admins"),
    adminFindings: FortiFinding[] = admins
      .filter((row) => !row.trustHosts)
      .map((row) =>
        finding(
          `محدودیت مبدا برای ${row.name} مشاهده نشد`,
          row.profile === "super_admin" ? "high" : "medium",
          `profile=${row.profile ?? "unknown"}`,
          "trusthost و مجوز حساب مدیریت را متناسب با شبکهٔ مجاز بررسی کنید.",
        ),
      );
  add(
    "admin_security",
    "حساب‌های مدیریتی",
    ["admins"],
    admins.length > 0,
    [
      { label: "مدیران", value: String(admins.length) },
      { label: "دارای trusthost", value: String(admins.filter((row) => !!row.trustHosts).length) },
    ],
    adminFindings,
  );
  const status: FortiCheckStatus = sections.some((s) => s.status === "critical")
    ? "critical"
    : sections.some((s) => s.status === "needs_review")
      ? "needs_review"
      : sections.every((s) => s.status === "safe" && s.coverage === "complete")
        ? "safe"
        : sections.every((s) => s.status === "not_supported")
          ? "not_supported"
          : "not_checked";
  return {
    collectedAt: collection.collectedAt,
    status,
    coverage: sections.every((s) => s.coverage === "complete")
      ? ("complete" as const)
      : ("partial" as const),
    summary:
      status === "safe"
        ? "هر هشت بخش با شواهد کامل بررسی شد و یافتهٔ مهمی مشاهده نشد."
        : status === "not_checked"
          ? "گزارش کامل نیست؛ برای نتیجه‌گیری، بخش‌های فاقد شواهد را بررسی کنید."
          : "گزارش بر اساس شواهد موجود، مواردی برای بررسی دارد.",
    sections,
    findings: sections.flatMap((s) => s.findings),
  };
}
