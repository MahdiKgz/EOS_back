export const ACTIVITY_FROM = `FROM "device_backup_events" event JOIN "devices" device ON event."deviceId" = device."id"
  LEFT JOIN "device_companies" company ON company."id" = device."companyId" AND company."workspaceOwnerId" = $1
  LEFT JOIN "device_backups" file ON file."id" = event."backupId" AND file."deviceId" = device."id" AND file."workspaceOwnerId" = $1`;
export const ACTIVITY_WHERE = `device."workspaceOwnerId" = $1 AND device."deletedAt" IS NULL
  AND ($2::text IS NULL OR device."companyId" = $2)
  AND ($3::text IS NULL OR event."action" = $3)
  AND ($4::text IS NULL OR event."actorName" ILIKE $4 ESCAPE '\\' OR event."actorUsername" ILIKE $4 ESCAPE '\\'
    OR COALESCE(event."deviceName", device."name") ILIKE $4 ESCAPE '\\' OR COALESCE(event."host", device."host") ILIKE $4 ESCAPE '\\'
    OR COALESCE(event."vendor", device."vendor") ILIKE $4 ESCAPE '\\' OR COALESCE(event."filename", file."filename") ILIKE $4 ESCAPE '\\')
  AND ($5::bigint IS NULL OR event."id" = $5)`;
export function activityParameters(
  workspace: string,
  input: { companyId?: string; event?: string; search?: string; eventId?: string },
) {
  const search = input.search ? `%${input.search.replace(/[\\%_]/g, "\\$&")}%` : null;
  return [workspace, input.companyId ?? null, input.event ?? null, search, input.eventId ?? null];
}
