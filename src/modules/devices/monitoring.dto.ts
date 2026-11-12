import { IsBoolean, IsIn, IsInt, IsOptional, IsUUID } from "class-validator";
export class SaveMonitoringDto {
  @IsBoolean() enabled!: boolean;
  @IsInt() @IsIn([60, 300, 900]) intervalSeconds!: number;
  @IsOptional() @IsUUID("4") revision?: string;
}
export class MonitoringQueryDto {
  @IsOptional() @IsIn(["1h", "24h", "7d", "30d"]) range: "1h" | "24h" | "7d" | "30d" = "24h";
}
