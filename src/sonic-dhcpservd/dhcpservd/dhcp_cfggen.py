#!/usr/bin/env python

import ipaddress
import json
import syslog

from jinja2 import Environment, FileSystemLoader
from .dhcp_server_utils import merge_intervals

PORT_MAP_PATH = "/tmp/port-name-alias-map.txt"
UNICODE_TYPE = str
DHCP_SERVER_IPV4 = "DHCP_SERVER_IPV4"
DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS = "DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS"
DHCP_SERVER_IPV4_RANGE = "DHCP_SERVER_IPV4_RANGE"
DHCP_SERVER_IPV4_PORT = "DHCP_SERVER_IPV4_PORT"
DHCP_SERVER_IPV4_LEASE = "DHCP_SERVER_IPV4_LEASE"
DHCP_SERVER_IP_PORTS_FILE = "/tmp/dhcp_server_ip_ports.json"
LEASE_UPDATE_SCRIPT_PATH = "/etc/kea/lease_update.sh"
DEFAULT_LEASE_PATH = "/tmp/kea-lease.csv"
KEA_DHCP4_CONF_TEMPLATE_PATH = "/usr/share/sonic/templates/"
KEA_TEMPLATE = "kea-dhcp4.conf.j2"
# Default lease time of DHCP
DEFAULT_LEASE_TIME = 900


class DhcpServCfgGenerator(object):
    def __init__(self, dhcp_db_connector):
        # Read port alias map file, this file is render after container start, so it would not change any more
        self.port_alias_map = {}
        self.db_connector = dhcp_db_connector
        with open(PORT_MAP_PATH, "r") as file:
            lines = file.readlines()
            for line in lines:
                splits = line.strip().split(" ")
                if len(splits) != 2:
                    continue
                self.port_alias_map[splits[0]] = splits[1]
        # Get kea config template
        env = Environment(loader=FileSystemLoader(KEA_DHCP4_CONF_TEMPLATE_PATH))
        self.kea_template = env.get_template(KEA_TEMPLATE)

    def _get_dhcp_ipv4_tables_from_db(self):
        """
        Get DHCP Server IPv4 related table from config_db.
        Returns:
            Four table objects.
        """
        dhcp_server_ipv4 = self.db_connector.get_config_db_table(DHCP_SERVER_IPV4)
        customized_options_ipv4 = self.db_connector.get_config_db_table(DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS)
        range_ipv4 = self.db_connector.get_config_db_table(DHCP_SERVER_IPV4_RANGE)
        port_ipv4 = self.db_connector.get_config_db_table(DHCP_SERVER_IPV4_PORT)
        return dhcp_server_ipv4, customized_options_ipv4, range_ipv4, port_ipv4

    def _get_vlan_ipv4_interface(self, vlan_interface_keys):
        """
        Get ipv4 info of vlans
        Args:
            vlan_interface_keys: Keys of vlan_interfaces, sample:
                [
                    "Vlan1000|192.168.0.1/21",
                    "Vlan1000|fc02:1000::1/64"
                ]
        Returns:
            Vlans infomation, sample:
                {
                    'Vlan1000': [{
                        'network': IPv4Network('192.168.0.0/24'),
                        'ip': '192.168.0.1/24'
                    }]
                }
        """
        ret = {}
        for key in vlan_interface_keys:
            splits = key.split("|")
            # Skip with no ip address
            if len(splits) != 2:
                continue
            network = ipaddress.ip_network(UNICODE_TYPE(splits[1]), False)
            # Skip ipv6
            if network.version != 4:
                continue
            if key not in ret:
                ret[splits[0]] = []
            ret[splits[0]].append({"network": network, "ip": splits[1]})
        return ret

    def _parse_range(self, range_ipv4):
        """
        Parse content in DHCP_SERVER_IPV4_RANGE table to below format:
        {
            'range2': [IPv4Address('192.168.0.3'), IPv4Address('192.168.0.6')],
            'range1': [IPv4Address('192.168.0.2'), IPv4Address('192.168.0.5')],
            'range3': [IPv4Address('192.168.0.10'), IPv4Address('192.168.0.10')]
        }
        Args:
            range_ipv4: Table object or dict of range.
        """
        self.ranges = {}
        for range in list(range_ipv4.keys()):
            curr_range = range_ipv4.get(range, {}).get("range", {})
            if len(curr_range) != 2:
                syslog.syslog(syslog.LOG_WARNING, f"Length of {curr_range} != 2")
                continue
            address_1 = ipaddress.ip_address(curr_range[0])
            address_2 = ipaddress.ip_address(curr_range[1])
            # To make sure order of range is correct
            range_start = address_1 if address_1 < address_2 else address_2
            range_end = address_2 if address_1 < address_2 else address_1
            self.ranges[range] = [range_start, range_end]

    def _parse_customized_options(self, customized_options_ipv4):
        """
        Parse content in DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS table.
        Args:
            customized_options_ipv4: Table object or dict of customized options.
        """
        # TODO validate option type
        self.customized_options = {}
        for option in list(customized_options_ipv4.keys()):
            self.customized_options[option] = customized_options_ipv4.get(option, {})

    def _match_range_network(self, dhcp_interface, dhcp_interface_name, port, range):
        """
        Loop the IP of the dhcp interface and find the network that target range is in this network. And to construct
        below data to record range - port map
        {
            'Vlan1000': {
                '192.168.0.1/24': {
                    'etp2': [
                        [IPv4Address('192.168.0.7'), IPv4Address('192.168.0.7')]
                    ]
                }
            }
        }
        Args:
            dhcp_interface: Ip and network information of current DHCP interface, sample:
                [{
                    'network': IPv4Network('192.168.0.0/24'),
                    'ip': '192.168.0.1/24'
                }]
            dhcp_interface_name: Name of DHCP interface.
            port: Name of DHCP member port.
            range: Ip Range, sample:
                [IPv4Address('192.168.0.2'), IPv4Address('192.168.0.5')]
        """
        for dhcp_interface_ip in dhcp_interface:
            if not range[0] in dhcp_interface_ip["network"] or \
               not range[1] in dhcp_interface_ip["network"]:
                continue
            dhcp_interface_ip_str = dhcp_interface_ip["ip"]
            if dhcp_interface_ip_str not in self.port_ips[dhcp_interface_name]:
                self.port_ips[dhcp_interface_name][dhcp_interface_ip_str] = {}
            if port not in self.port_ips[dhcp_interface_name][dhcp_interface_ip_str]:
                self.port_ips[dhcp_interface_name][dhcp_interface_ip_str][port] = []
            self.port_ips[dhcp_interface_name][dhcp_interface_ip_str][port].append([range[0], range[1]])
            break

    def _parse_port(self, port_ipv4, vlan_interfaces, vlan_members):
        """
        Parse content in DHCP_SERVER_IPV4_PORT table to below format, which indicate ip ranges assign to interface.
        self.port_ips = {
            'Vlan1000': {
                '192.168.0.1/24': {
                    'etp2': [
                        [IPv4Address('192.168.0.7'), IPv4Address('192.168.0.7')]
                    ],
                    'etp3': [
                        [IPv4Address('192.168.0.2'), IPv4Address('192.168.0.6')],
                        [IPv4Address('192.168.0.10'), IPv4Address('192.168.0.10')]
                    ]
                }
            }
        }
        self.ip_ports = {
            IPv4Network('192.168.0.0/24'): "Vlan1000"
        }
        Args:
            port_ipv4: Table object.
            vlan_interfaces: Vlan information, sample:
                {
                    'Vlan1000': [{
                        'network': IPv4Network('192.168.0.0/24'),
                        'ip': '192.168.0.1/24'
                    }]
                }
        """
        self.port_ips = {}
        self.ip_ports = {}
        for port_key in list(port_ipv4.keys()):
            port_config = port_ipv4.get(port_key, {})
            # Cannot specify both 'ips' and 'ranges'
            if "ips" in port_config and len(port_config["ips"]) != 0 and "ranges" in port_config \
               and len(port_config["ranges"]) != 0:
                syslog.syslog(syslog.LOG_WARNING, f"Port config for {port_key} contains both ips and ranges, skip")
                continue
            splits = port_key.split("|")
            # Skip port not in correct vlan
            if port_key not in vlan_members:
                syslog.syslog(syslog.LOG_WARNING, f"Port {splits[1]} is not in {splits[0]}")
                continue
            # Get dhcp interface name like Vlan1000
            dhcp_interface_name = splits[0]
            # Get dhcp member interface name like etp1
            if splits[1] not in self.port_alias_map:
                syslog.syslog(syslog.LOG_WARNING, f"Cannot find {splits[1]} in port_alias_map")
                continue
            port = self.port_alias_map[splits[1]]
            if dhcp_interface_name not in self.port_ips:
                self.port_ips[dhcp_interface_name] = {}
            # Get ip information of Vlan
            dhcp_interface = vlan_interfaces[dhcp_interface_name]

            for dhcp_interface_ip in dhcp_interface:
                self.ip_ports[dhcp_interface_ip["network"]] = dhcp_interface_name

            if "ips" in port_config and len(port_config["ips"]) != 0:
                for ip in set(port_config["ips"]):
                    ip_address = ipaddress.ip_address(ip)
                    # Loop the IP of the dhcp interface and find the network that target ip is in this network.
                    self._match_range_network(dhcp_interface, dhcp_interface_name, port, [ip_address, ip_address])
            if "ranges" in port_config and len(port_config["ranges"]) != 0:
                for range_name in list(port_config["ranges"]):
                    if range_name not in self.ranges:
                        syslog.syslog(syslog.LOG_WARNING, f"Range {range_name} is not in range table, skip")
                        continue
                    range = self.ranges[range_name]
                    # Loop the IP of the dhcp interface and find the network that target range is in this network.
                    self._match_range_network(dhcp_interface, dhcp_interface_name, port, range)
        # Merge ranges to avoid overlap
        for dhcp_interface_name, value in self.port_ips.items():
            for dhcp_interface_ip, port_range in value.items():
                for port_name, ip_range in port_range.items():
                    ranges = merge_intervals(ip_range)
                    ranges = [[str(range[0]), str(range[1])] for range in ranges]
                    self.port_ips[dhcp_interface_name][dhcp_interface_ip][port_name] = ranges
                self.port_ips[dhcp_interface_name][dhcp_interface_ip]["subnet"] = \
                    str(ipaddress.ip_network(dhcp_interface_ip, strict=False))

        # Store network - dhcp port map file which would be used by dhcpservd while updating lease table
        ip_ports = {}
        for key, value in self.ip_ports.items():
            ip_ports[str(key)] = value
        with open(DHCP_SERVER_IP_PORTS_FILE, "w") as write_file:
            json.dump(ip_ports, write_file, indent=4, ensure_ascii=False)

    def generate_kea_dhcp4_config(self):
        """
        Generate kea-dhcp4 config
        Args:
            from_db: boolean, if set to True, generate config from running config_db
            config_file_path: str, if from_db is False, generate config from config_db file
        Returns:
            config dict
        """
        # Generate from running config_db
        # Get host name
        device_metadata = self.db_connector.get_config_db_table("DEVICE_METADATA")
        localhost_entry = device_metadata.get("localhost", {})
        if localhost_entry is None or "hostname" not in localhost_entry:
            syslog.syslog(syslog.LOG_ERR, "Cannot get hostname")
            return None
        hostname = localhost_entry["hostname"]
        # Get ip information of vlan
        vlan_interface = self.db_connector.get_config_db_table("VLAN_INTERFACE")
        vlan_interface_keys = set(vlan_interface.keys())
        vlan_interfaces = self._get_vlan_ipv4_interface(vlan_interface_keys)
        dhcp_server_ipv4, customized_options_ipv4, range_ipv4, port_ipv4 = self._get_dhcp_ipv4_tables_from_db()
        vlan_member_table = self.db_connector.get_config_db_table("VLAN_MEMBER")
        vlan_members = set(vlan_member_table.keys())

        # Parse range table
        self._parse_range(range_ipv4)

        # Parse customized options table
        self._parse_customized_options(customized_options_ipv4)

        # Parse port table
        self._parse_port(port_ipv4, vlan_interfaces, vlan_members)

        for vlan_interface in list(vlan_interfaces.keys()):
            for index in list(range(len(vlan_interfaces[vlan_interface]))):
                vlan_interfaces[vlan_interface][index]["network"] = \
                    str(vlan_interfaces[vlan_interface][index]["network"])
        # Render config
        j2_obj = {
            "dhcp_server_ipv4": dhcp_server_ipv4,
            "vlan_interface": vlan_interfaces,
            "port_ips": self.port_ips,
            "default_lease_time": DEFAULT_LEASE_TIME,
            "hostname": hostname,
            "lease_path": DEFAULT_LEASE_PATH,
            "lease_update_script_path": LEASE_UPDATE_SCRIPT_PATH
        }
        output = self.kea_template.render(j2_obj)
        return output
