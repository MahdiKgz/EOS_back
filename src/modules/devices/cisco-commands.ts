export const CISCO_IOSXE_READ_COMMANDS = Object.freeze({
  platform: "show version",
  inventory: "show inventory",
  interfacesStatus: "show interfaces status",
  interfacesErrors: "show interfaces counters errors",
  interfacesDetailed: "show interfaces",
  runningConfigHostname: "show running-config | include ^hostname",
  runningConfig: "show running-config",
  startupConfig: "show startup-config",
  ipInterfaceBrief: "show ip interface brief",
  vlanBrief: "show vlan brief",
  trunk: "show interfaces trunk",
  etherchannel: "show etherchannel summary",
  spanningTree: "show spanning-tree summary",
  route: "show ip route",
  arp: "show ip arp",
  macAddressTable: "show mac address-table",
  cdpNeighbors: "show cdp neighbors detail",
  lldpNeighbors: "show lldp neighbors detail",
  ospfNeighbors: "show ip ospf neighbor",
  eigrpNeighbors: "show ip eigrp neighbors",
  bgpSummary: "show ip bgp summary",
  acl: "show access-lists",
  nat: "show ip nat translations",
  dhcpPools: "show ip dhcp pool",
  dhcpBindings: "show ip dhcp binding",
  hosts: "show hosts",
  aaa: "show aaa servers",
  localUsers: "show running-config | include ^username",
  sshStatus: "show ip ssh",
  snmp: "show snmp",
  logging: "show logging",
  ntpStatus: "show ntp status",
  clock: "show clock detail",
  cpu: "show processes cpu",
  memory: "show processes memory",
  licenseSummary: "show license summary",
  flash: "dir flash:",
  runningConfigMetadata:
    "show running-config | include ^version|^hostname|^boot|^service timestamps|^ntp server|^logging host|^snmp-server",
  startupConfigMetadata:
    "show startup-config | include ^version|^hostname|^boot|^service timestamps|^ntp server|^logging host|^snmp-server",
} as const);

export type CiscoReadCommandId = keyof typeof CISCO_IOSXE_READ_COMMANDS;

export function ciscoReadCommand(id: CiscoReadCommandId) {
  return CISCO_IOSXE_READ_COMMANDS[id];
}
