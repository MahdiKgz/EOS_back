import { IsBoolean, IsInt, IsString, IsUUID, Max, MaxLength, Min, Equals } from "class-validator";
import { Type } from "class-transformer";
export class TerminalSizeDto {
  @IsInt() @Min(20) @Max(240) cols!: number;
  @IsInt() @Min(5) @Max(80) rows!: number;
}
export class OpenTerminalDto extends TerminalSizeDto {
  @IsUUID("4") previewId!: string;
  @Equals("execute") intent!: string;
  @IsBoolean() @Equals(true) confirmed!: boolean;
}
export class TerminalInputDto {
  @IsInt() @Min(1) @Max(Number.MAX_SAFE_INTEGER) sequence!: number;
  @IsString() @MaxLength(32768) data!: string;
}
export class TerminalReadDto {
  @Type(() => Number) @IsInt() @Min(0) @Max(Number.MAX_SAFE_INTEGER) cursor = 0;
}
