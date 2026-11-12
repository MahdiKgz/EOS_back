import { Transform, Type } from "class-transformer";
import { IsIn, IsInt, IsOptional, IsString, IsUUID, Max, MaxLength, Min } from "class-validator";
import { supportStates, type SupportState } from "./vendor-catalog";
const trim = ({ value }: { value: unknown }) => (typeof value === "string" ? value.trim() : value);
class VendorCompanyQuery {
  @IsOptional() @IsUUID("4") companyId?: string;
}
export class VendorCatalogQuery extends VendorCompanyQuery {
  @IsOptional() @Transform(trim) @IsString() @MaxLength(120) search?: string;
  @IsOptional() @IsIn(supportStates) state?: SupportState;
}
export class VendorDevicesQuery extends VendorCompanyQuery {
  @IsOptional() @Transform(trim) @IsString() @MaxLength(120) search?: string;
  @IsOptional() @IsIn(["unknown", "online", "offline", "error"]) status?: string;
  @Type(() => Number) @IsInt() @Min(1) @Max(100000) page = 1;
  @Type(() => Number) @IsInt() @IsIn([10, 20, 50, 100]) pageSize = 20;
}
