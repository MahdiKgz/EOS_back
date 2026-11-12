import { fortiVdomActions } from "./fortigate-vdom";
import { fortiClusterActions } from "./fortigate-cluster";
import { fortiAdminActions } from "./fortigate-admin";
import { fortiNetworkActions } from "./fortigate-network";
import { fortiPolicyActions } from "./fortigate-policy";
import { fortiObjectActions } from "./fortigate-object-compiler";
import { Transform } from "class-transformer";
import {
  IsIn,
  IsString,
  Length,
  Matches,
  IsOptional,
  IsBoolean,
  Equals,
  IsUUID,
} from "class-validator";
export const fortiInterfaceActions = [
  "interface.alias",
  "interface.role",
  "interface.state",
  "interface.ip",
  "interface.vlan",
  "interface.allowaccess",
] as const;
export class PreviewFortiActionDto {
  @IsIn([
    ...fortiInterfaceActions,
    ...fortiObjectActions,
    ...fortiPolicyActions,
    ...fortiNetworkActions,
    ...fortiAdminActions,
    ...fortiClusterActions,
    ...fortiVdomActions,
  ])
  action!:
    | (typeof fortiInterfaceActions)[number]
    | (typeof fortiObjectActions)[number]
    | (typeof fortiPolicyActions)[number]
    | (typeof fortiNetworkActions)[number]
    | (typeof fortiAdminActions)[number]
    | (typeof fortiClusterActions)[number]
    | (typeof fortiVdomActions)[number];
  @Transform(({ value }: { value: unknown }) => (typeof value === "string" ? value.trim() : value))
  @IsString()
  @Matches(/^[A-Za-z0-9_.:-]{1,79}$/)
  name!: string;
  @IsString() @Length(0, 4096) value: string = "";
  @IsOptional() @IsString() @Matches(/^[A-Za-z0-9_.:-]{1,79}$/) vdom?: string;
  @IsOptional() @IsString() @Matches(/^[A-Za-z0-9_.:-]{1,79}$/) parent?: string;
  @IsOptional() @IsString() @Matches(/^\d{1,4}$/) vlanId?: string;
  @IsOptional()
  @IsIn(["subnet", "iprange", "fqdn", "wildcard-fqdn", "geography"])
  addressType?: string;
  @IsOptional() @IsString() @Length(1, 39) endIp?: string;
  @IsOptional() @IsIn(["TCP", "UDP", "TCP-UDP"]) serviceProtocol?: string;
  @IsOptional() @IsString() @Length(1, 4096) udpPorts?: string;
  @IsOptional() @IsString() @Length(1, 5) start?: string;
  @IsOptional() @IsString() @Length(1, 5) end?: string;
  @IsOptional() @IsIn(["deny", "allow"]) intrazone?: string;
  @IsOptional() @IsString() @Length(1, 4096) srcInterface?: string;
  @IsOptional() @IsString() @Length(1, 4096) dstInterface?: string;
  @IsOptional() @IsString() @Length(1, 4096) srcAddresses?: string;
  @IsOptional() @IsString() @Length(1, 4096) dstAddresses?: string;
  @IsOptional() @IsString() @Length(1, 4096) services?: string;
  @IsOptional() @IsString() @Length(1, 79) schedule?: string;
  @IsOptional() @IsIn(["accept", "deny"]) policyAction?: string;
  @IsOptional() @IsBoolean() nat?: boolean;
  @IsOptional() @IsIn(["all", "utm", "disable"]) logTraffic?: string;
  @IsOptional() @IsIn(["enable", "disable"]) policyStatus?: string;
  @IsOptional() @IsString() @Length(1, 32) sourceCidr?: string;
  @IsOptional() @IsString() @Matches(/^[1-9]\d{0,9}$/) relativeTo?: string;
  @IsOptional() @IsIn(["before", "after"]) position?: string;
  @IsOptional() @IsString() @Matches(/^[A-Za-z0-9_.:-]{1,31}$/) targetVdom?: string;
  @IsOptional() @IsString() @Length(0, 11) vdomShortName?: string;
  @IsOptional() @IsString() @Length(0, 127) vdomDescription?: string;
  @IsOptional() @IsIn(["standalone", "a-a", "a-p"]) haMode?: string;
  @IsOptional() @IsString() @Length(1, 32) haGroup?: string;
  @IsOptional() @IsString() @Matches(/^\d{1,3}$/) haPriority?: string;
  @IsOptional() @IsString() @Length(1, 35) sdwanZone?: string;
  @IsOptional() @IsString() @Length(1, 1024) sdwanMembers?: string;
  @IsOptional() @IsString() @Length(1, 253) probeServer?: string;
  @IsOptional() @IsString() @Length(1, 35) adminProfile?: string;
  @IsOptional() @IsString() @Length(1, 4096) accountVdoms?: string;
  @IsOptional() @IsUUID("4") adminSecretId?: string;
  @IsOptional() @IsString() @Length(1, 32) destinationCidr?: string;
  @IsOptional() @IsString() @Length(1, 39) gateway?: string;
  @IsOptional() @IsString() @Length(1, 39) primaryDns?: string;
  @IsOptional() @IsString() @Length(1, 39) secondaryDns?: string;
  @IsOptional() @IsString() @Length(1, 253) ntpServer?: string;
  @IsOptional() @IsString() @Length(1, 39) externalIp?: string;
  @IsOptional() @IsString() @Length(1, 39) mappedIp?: string;
  @IsOptional() @IsString() @Matches(/^\d{1,5}$/) externalPort?: string;
  @IsOptional() @IsString() @Matches(/^\d{1,5}$/) mappedPort?: string;
}
export class ExecuteFortiActionDto {
  @Equals("execute") intent!: "execute";
  @IsBoolean() @Equals(true) confirmed!: true;
}
