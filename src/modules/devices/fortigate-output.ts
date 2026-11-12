import { redactCiscoCredentials } from "./cisco-access-error";
export function redactFortiOutput(value: string, password?: string) {
  let quoted = false;
  const lines: string[] = [];
  for (const line of value.split(/\r?\n/)) {
    if (quoted) {
      if (/(?:^|[^\\])"/.test(line)) quoted = false;
      continue;
    }
    const match = line.match(
      /^(\s*set\s+(?:password|passwd|secret|psksecret|private-key|api-key|token|auth-passwd|priv-passwd|community|server-secret|bind-password|client-secret|key|passphrase)\s+)(.*)$/i,
    );
    if (match) {
      lines.push(match[1] + "[REDACTED]");
      quoted = match[2].startsWith('"') && !/(?:^|[^\\])"/.test(match[2].slice(1));
    } else lines.push(line.replace(/\bENC\s+\S+/gi, "ENC [REDACTED]"));
  }
  return redactCiscoCredentials(
    lines
      .join("\n")
      .replace(
        /^([^\r\n]*?\b(?:(?:auth|enc|dec)[-_ ]?key|key|psksecret|secret|password)\s*[=:]\s*).*$/gim,
        "$1[REDACTED]",
      ),
    [password],
  );
}

// Scrub device-controlled values after parsing. A password such as "Version" must not erase the identity header before it is interpreted.
export function sanitizeFortiReport<T>(value: T, password?: string): T {
  if (!password) return value;
  const fixed = new Set([
    "vendor",
    "platform",
    "collectedAt",
    "inventoryStatus",
    "state",
    "status",
    "coverage",
    "warnings",
    "commandId",
    "errorCode",
    "key",
    "columns",
    "sources",
  ]);
  const visit = (item: unknown, key: string): unknown => {
    if (fixed.has(key)) return item;
    if (typeof item === "string") return redactCiscoCredentials(item, [password]);
    if (Array.isArray(item)) return item.map((entry) => visit(entry, key));
    if (item && typeof item === "object")
      return Object.fromEntries(
        Object.entries(item).map(([field, entry]) => [field, visit(entry, field)]),
      );
    return item;
  };
  return visit(value, "") as T;
}
