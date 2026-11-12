import { redactFortiOutput } from "./fortigate-output";
export const FORTIGATE_LOG_PREPARATION = [
  "execute log filter reset",
  "execute log filter view-lines 500",
] as const;
export type FortiLog = {
  date: string | null;
  time: string | null;
  timezone: string | null;
  eventTime: string | null;
  type: string | null;
  subtype: string | null;
  level: string | null;
  vdom: string | null;
  description: string | null;
  message: string | null;
  user: string | null;
  sourceIp: string | null;
  destinationIp: string | null;
  action: string | null;
  raw: string;
};
export function parseFortiLogs(text: string) {
  const entries: FortiLog[] = [];
  for (const line of text.split(/\r?\n/)) {
    const fields: Record<string, string> = {};
    for (const match of line.matchAll(
      /\b([a-z][a-z0-9_-]{0,40})=(?:"((?:\\.|[^"\\])*)"|([^\s]+))/gi,
    ))
      fields[match[1].toLowerCase()] = (match[2] ?? match[3])
        .replace(/\\(["\\])/g, "$1")
        .slice(0, 1024);
    if (!fields.date && !fields.eventtime && !fields.logid) continue;
    entries.push({
      date: fields.date ?? null,
      time: fields.time ?? null,
      timezone: fields.tz ?? null,
      eventTime: fields.eventtime ?? null,
      type: fields.type ?? null,
      subtype: fields.subtype ?? null,
      level: fields.level ?? null,
      vdom: fields.vd ?? null,
      description: fields.logdesc ?? null,
      message: fields.msg ?? null,
      user: fields.user ?? null,
      sourceIp: fields.srcip ?? null,
      destinationIp: fields.dstip ?? null,
      action: fields.action ?? null,
      raw: redactFortiOutput(line).slice(0, 2048),
    });
    if (entries.length === 500) break;
  }
  const count = text.match(/(\d+)\s+logs?\s+found/i)?.[1];
  return {
    entries,
    rawLines: text.split(/\r?\n/).filter(Boolean).slice(0, 510),
    reportedTotal: count && Number.isSafeInteger(Number(count)) ? Number(count) : null,
    limit: 500,
    order: "device" as const,
  };
}
