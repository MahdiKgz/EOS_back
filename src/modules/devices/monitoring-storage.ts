import type { EntityManager } from "typeorm";
import type { Measurement } from "./monitoring.types";

export async function storeMeasurements(
  manager: EntityManager,
  deviceId: string,
  companyId: string | null,
  generation: string,
  epoch: string,
  at: string,
  values: Measurement[],
) {
  for (const value of values)
    await manager.query(
      `INSERT INTO "device_metric_buckets"
    ("deviceId","companyKey","generation","counterEpoch","metricKey","label","unit","kind","resolution","bucketAt","firstAt","lastAt","firstValue","lastValue","sumValue","sampleCount")
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,300,to_timestamp(floor(extract(epoch from $9::timestamptz)/300)*300),$9,$9,$10,$10,$10,1)
    ON CONFLICT ("deviceId","companyKey","generation","counterEpoch","metricKey","label","resolution","bucketAt") DO UPDATE SET
    "lastAt"=EXCLUDED."lastAt","lastValue"=EXCLUDED."lastValue","sumValue"="device_metric_buckets"."sumValue"+EXCLUDED."sumValue","sampleCount"="device_metric_buckets"."sampleCount"+1`,
      [
        deviceId,
        companyId ?? "",
        generation,
        value.kind === "counter" ? epoch : "",
        value.key,
        value.label,
        value.unit,
        value.kind,
        at,
        value.value,
      ],
    );
  // One hour buckets retain older data without multiplying rows indefinitely.
  await manager.query(
    `WITH old AS (
    DELETE FROM "device_metric_buckets" WHERE "deviceId"=$1 AND "resolution"=300 AND "bucketAt"<now()-interval '24 hours' RETURNING *
  ), grouped AS (
    SELECT "deviceId","companyKey","generation","counterEpoch","metricKey","label","unit","kind",date_trunc('hour',"bucketAt") AS hour,
    min("firstAt") AS first_at,max("lastAt") AS last_at,(array_agg("firstValue" ORDER BY "firstAt"))[1] AS first_value,
    (array_agg("lastValue" ORDER BY "lastAt" DESC))[1] AS last_value,sum("sumValue") AS total,sum("sampleCount") AS count
    FROM old GROUP BY "deviceId","companyKey","generation","counterEpoch","metricKey","label","unit","kind",hour
  ) INSERT INTO "device_metric_buckets"
    ("deviceId","companyKey","generation","counterEpoch","metricKey","label","unit","kind","resolution","bucketAt","firstAt","lastAt","firstValue","lastValue","sumValue","sampleCount")
    SELECT "deviceId","companyKey","generation","counterEpoch","metricKey","label","unit","kind",3600,hour,first_at,last_at,first_value,last_value,total,count FROM grouped
    ON CONFLICT ("deviceId","companyKey","generation","counterEpoch","metricKey","label","resolution","bucketAt") DO UPDATE SET
    "firstValue"=CASE WHEN EXCLUDED."firstAt"<"device_metric_buckets"."firstAt" THEN EXCLUDED."firstValue" ELSE "device_metric_buckets"."firstValue" END,
    "lastValue"=CASE WHEN EXCLUDED."lastAt">"device_metric_buckets"."lastAt" THEN EXCLUDED."lastValue" ELSE "device_metric_buckets"."lastValue" END,
    "firstAt"=least(EXCLUDED."firstAt","device_metric_buckets"."firstAt"),"lastAt"=greatest(EXCLUDED."lastAt","device_metric_buckets"."lastAt"),
    "sumValue"="device_metric_buckets"."sumValue"+EXCLUDED."sumValue","sampleCount"="device_metric_buckets"."sampleCount"+EXCLUDED."sampleCount"`,
    [deviceId],
  );
  await manager.query(
    `DELETE FROM "device_metric_buckets" WHERE "deviceId"=$1 AND "bucketAt"<now()-interval '30 days'`,
    [deviceId],
  );
}
export type MetricRow = {
  metricKey: string;
  label: string;
  unit: string;
  kind: "counter" | "gauge";
  counterEpoch: string;
  bucketAt: Date;
  firstAt: Date;
  lastAt: Date;
  firstValue: number;
  lastValue: number;
  sumValue: number;
  sampleCount: number;
};
export function metricSeries(rows: MetricRow[]) {
  const series = new Map<
    string,
    {
      key: string;
      label: string;
      unit: string;
      points: { at: string; value: number; epoch: string }[];
    }
  >();
  const previous = new Map<string, MetricRow>();
  for (const row of rows) {
    const key = row.metricKey + "\0" + row.label;
    let group = series.get(key);
    if (!group) {
      group = {
        key: row.kind === "counter" ? row.metricKey.replace(/_bytes$/, "_mbps") : row.metricKey,
        label: row.label,
        unit: row.kind === "counter" ? "Mbps" : row.unit,
        points: [],
      };
      series.set(key, group);
    }
    if (row.kind === "gauge")
      group.points.push({
        at: new Date(row.lastAt).toISOString(),
        value: row.sumValue / row.sampleCount,
        epoch: "",
      });
    else {
      const last = previous.get(key + row.counterEpoch),
        elapsed = last ? (+new Date(row.lastAt) - +new Date(last.lastAt)) / 1000 : 0;
      if (last && elapsed > 0 && elapsed <= 7200 && row.lastValue >= last.lastValue)
        group.points.push({
          at: new Date(row.lastAt).toISOString(),
          value: ((row.lastValue - last.lastValue) * 8) / elapsed / 1e6,
          epoch: row.counterEpoch,
        });
      // A single bucket can contain several observations; its rate is still meaningful.
      else if (
        row.sampleCount > 1 &&
        +new Date(row.lastAt) > +new Date(row.firstAt) &&
        row.lastValue >= row.firstValue
      )
        group.points.push({
          at: new Date(row.lastAt).toISOString(),
          value:
            ((row.lastValue - row.firstValue) * 8) /
            ((+new Date(row.lastAt) - +new Date(row.firstAt)) / 1000) /
            1e6,
          epoch: row.counterEpoch,
        });
      previous.set(key + row.counterEpoch, row);
    }
  }
  return [...series.values()]
    .filter((s) => s.points.length)
    .map((s) => ({
      ...s,
      points: s.points.filter(
        (_, i) =>
          i % Math.max(1, Math.ceil(s.points.length / 240)) === 0 || i === s.points.length - 1,
      ),
    }));
}
