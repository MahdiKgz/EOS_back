import {
  isFortiVdomAction,
  compileFortiVdom,
  assertFortiVdom,
  fortiVdomBefore,
} from "./fortigate-vdom";
import {
  isFortiClusterAction,
  compileFortiCluster,
  assertFortiCluster,
  fortiClusterBefore,
  fortiClusterTarget,
  isFortiClusterAuto,
} from "./fortigate-cluster";
import {
  isFortiAdminAction,
  compileFortiAdmin,
  assertFortiAdmin,
  fortiAdminBefore,
} from "./fortigate-admin";
import {
  compileFortiNetwork,
  assertFortiNetwork,
  isFortiNetworkAction,
  isFortiNetworkCreate,
  fortiNetworkTarget,
  fortiNetworkBefore,
} from "./fortigate-network";
import { BadRequestException } from "@nestjs/common";
import { compileFortiInterface } from "./fortigate-action-compiler";
import {
  compileFortiObject,
  fortiResource,
  builtinServices,
  fortiActionMatches,
} from "./fortigate-object-compiler";
import {
  compileFortiPolicy,
  assertFortiPolicy,
  isFortiPolicyCreate,
  fortiPolicyTarget,
  fortiPolicyBefore,
  type FortiPreparedInput,
  type FortiDependencyTables,
} from "./fortigate-policy";
import type { FortiBlock } from "./fortigate-inventory";
export { fortiResource, fortiActionMatches };
export function compileFortiChange(
  input: FortiPreparedInput,
  row?: FortiBlock,
  tables: FortiDependencyTables = {},
) {
  const resource = fortiResource(input.action);
  const plan = input.action.startsWith("interface.")
    ? { ...compileFortiInterface(input), memberNames: [] as string[] }
    : isFortiVdomAction(input.action)
      ? compileFortiVdom(input)
      : isFortiClusterAction(input.action)
        ? compileFortiCluster(input)
        : isFortiAdminAction(input.action)
          ? compileFortiAdmin(input)
          : isFortiNetworkAction(input.action)
            ? compileFortiNetwork(input, tables)
            : input.action.startsWith("policy.")
              ? compileFortiPolicy(input, tables)
              : compileFortiObject(input, row);
  return {
    ...plan,
    ...resource,
    assignments: plan.assignments as Record<string, string>,
    create:
      isFortiAutomaticCreate(input.action) ||
      input.action.endsWith(".create") ||
      input.action === "interface.vlan",
    deleting: input.action.endsWith(".delete"),
  };
}
export function assertFortiChange(
  input: FortiPreparedInput,
  plan: ReturnType<typeof compileFortiChange>,
  rows: FortiBlock[],
  dependencies: FortiBlock[],
  tables: FortiDependencyTables = {},
) {
  if (isFortiVdomAction(input.action)) return assertFortiVdom(input, rows, tables);
  if (isFortiClusterAction(input.action)) return assertFortiCluster(input, rows, tables);
  if (isFortiAdminAction(input.action)) return assertFortiAdmin(input, rows, tables);
  if (isFortiNetworkAction(input.action)) return assertFortiNetwork(input, plan, rows, tables);
  if (input.action.startsWith("policy.")) return assertFortiPolicy(input, plan, rows, tables);
  const row = rows.find((row) => row.name === input.name);
  if (plan.create ? !!row : !row)
    throw new BadRequestException(
      plan.create
        ? "شیء هم‌نام موجود است؛ ایجاد جدید آن را بازنویسی نمی‌کند."
        : "هدف در پیکربندی زنده پیدا نشد.",
    );
  if (input.action === "interface.vlan" && !rows.some((row) => row.name === input.parent))
    throw new BadRequestException("رابط والد پیدا نشد.");
  if (
    plan.deleting &&
    ["address", "service", "zone"].includes(input.action.split(".")[0]) &&
    !row?.name.startsWith("firewall-log-analyzer") &&
    !Object.entries(row?.settings ?? {}).some(
      ([key, values]) =>
        ["comment", "description", "alias"].includes(key) &&
        values.join(" ").startsWith("firewall-log-analyzer"),
    )
  )
    throw new BadRequestException("این مسیر فقط اشیای مدیریت‌شدهٔ سامانه را حذف می‌کند.");
  for (const member of plan.memberNames) {
    const nested =
      input.action.startsWith("addressGroup.") || input.action.startsWith("serviceGroup.");
    if (
      !dependencies.some((row) => row.name === member) &&
      !(nested && rows.some((row) => row.name === member)) &&
      !(input.action.startsWith("serviceGroup.") && builtinServices.has(member.toUpperCase()))
    )
      throw new BadRequestException(`عضو ${member} در پیکربندی زنده پیدا نشد.`);
  }
  if (input.action.startsWith("addressGroup.") || input.action.startsWith("serviceGroup.")) {
    const graph = new Map(rows.map((row) => [row.name, row.settings.member ?? []]));
    graph.set(input.name, plan.assignments.member?.split(" ").filter(Boolean) ?? []);
    const visit = (name: string, path: Set<string>): boolean => {
      if (path.has(name)) return true;
      if (!graph.has(name)) return false;
      const next = new Set(path);
      next.add(name);
      return graph.get(name)!.some((child) => visit(child, next));
    };
    if (visit(input.name, new Set()))
      throw new BadRequestException("عضویت گروه‌ها حلقه ایجاد می‌کند.");
  }
}

export const isFortiAutomaticCreate = (action: string) =>
  isFortiPolicyCreate(action) || isFortiNetworkCreate(action) || isFortiClusterAuto(action);
export function fortiActionTarget(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
) {
  if (isFortiClusterAction(input.action)) return fortiClusterTarget(rows, input, expected);
  if (isFortiNetworkAction(input.action)) return fortiNetworkTarget(rows, input, expected);
  if (input.action.startsWith("policy.")) return fortiPolicyTarget(rows, input, expected);
  return rows.find((r) => r.name === input.name);
}
export function fortiActionBefore(
  rows: FortiBlock[],
  input: FortiPreparedInput,
  expected: Record<string, string>,
  tables: FortiDependencyTables,
) {
  if (isFortiVdomAction(input.action)) return fortiVdomBefore(rows, input, expected, tables);
  if (isFortiClusterAction(input.action)) return fortiClusterBefore(rows, input, expected);
  if (isFortiAdminAction(input.action)) return fortiAdminBefore(rows, input, expected);
  if (isFortiNetworkAction(input.action)) return fortiNetworkBefore(rows, input, expected, tables);
  return fortiPolicyBefore(rows, input, expected, tables);
}

export function fortiActionContexts(action: string, tables: FortiDependencyTables = {}) {
  const resource = fortiResource(action);
  return [
    ...new Set([
      resource.context,
      ...(resource.dependencies ?? (resource.dependency ? [resource.dependency] : [])),
    ]),
  ].filter(
    (context) =>
      context !== "system vdom" ||
      isFortiVdomAction(action) ||
      tables.__fortios?.[0]?.settings.vdomMode?.[0] !== "disabled",
  );
}
