#!/usr/bin/env python

import syslog
import ipaddress
import json

from dhcp_server_utils import DhcpDbConnector
from dhcp_server_utils import merge_intervals, get_keys, get_entry
from dhcp_server_utils import DHCP_SERVER_IP_PORTS_FILE, INIT_CONFIG_FILE

PORT_MAP_PATH = "/tmp/port-name-alias-map.txt"
UNICODE_TYPE = str
DHCP_SERVER_IPV4 = "DHCP_SERVER_IPV4"
DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS = "DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS"
DHCP_SERVER_IPV4_RANGE = "DHCP_SERVER_IPV4_RANGE"
DHCP_SERVER_IPV4_PORT = "DHCP_SERVER_IPV4_PORT"
DHCP_SERVER_IPV4_LEASE = "DHCP_SERVER_IPV4_LEASE"
# Default lease time of DHCP
DEFAULT_LEASE_TIME = 900


class DhcpServCfg(object):
    def __init__(self):
        # Read port alias map file
        self.port_alias_map = {}
        with open(PORT_MAP_PATH, "r") as file:
            lines = file.readlines()
            for line in lines:
                splits = line.strip().split(" ")
                if len(splits) != 2:
                    continue
                self.port_alias_map[splits[0]] = splits[1]

    def generate_relay_client_class(self, hostname):
        """
        Generate client class to classify requests from different physical interfaces, which is the base of ip
        assigning.
        Args:
            hostname: Host name of current device.
        Returns:
            Dict of client_class dict, sample:
                {
                    "etp1": {
                        "name": "hostname:etp1",
                        "test": "relay4[1].hex == 'hostname:etp1'"
                    }
                }
            This sample indicate that we will tag packet as "hostname:etp1" which circuit-id in DHCP packet is
            "hostname:etp1"
        """
        client_class = {}
        for key in list(self.port_alias_map.keys()):
            class_value = "{}:{}".format(hostname, self.port_alias_map[key])
            class_obj = {
                "name": class_value,
                "test":  "relay4[1].hex == '{}'".format(class_value)
            }
            client_class[self.port_alias_map[key]] = class_obj
        return client_class

    def get_dhcp_ipv4_tables_from_db(self):
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

    def get_vlan_ipv4_interface(self, vlan_interface_keys):
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

    def parse_range(self, range_ipv4):
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
        is_dict, keys = get_keys(range_ipv4)
        for range in keys:
            if is_dict:
                curr_range = range_ipv4.get(range, {}).get("range", {})
            else:
                curr_range = get_entry(range_ipv4, range)["range"].split(",")
            if len(curr_range) != 2:
                syslog.syslog(syslog.LOG_WARNING, f"Length of {curr_range} != 2")
                continue
            address_1 = ipaddress.ip_address(curr_range[0])
            address_2 = ipaddress.ip_address(curr_range[1])
            # To make sure order of range is correct
            range_start = address_1 if address_1 < address_2 else address_2
            range_end = address_2 if address_1 < address_2 else address_1
            self.ranges[range] = [range_start, range_end]

    def parse_customized_options(self, customized_options_ipv4):
        """
        Parse content in DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS table.
        Args:
            customized_options_ipv4: Table object or dict of customized options.
        """
        # TODO validate option type
        self.customized_options = {}
        is_dict, keys = get_keys(customized_options_ipv4)
        for option in keys:
            self.customized_options[option] = customized_options_ipv4.get(option, {}) if is_dict \
                else get_entry(customized_options_ipv4, option)

    def match_range_network(self, dhcp_interface, dhcp_interface_name, port, range):
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

    def parse_port(self, port_ipv4, vlan_interfaces, vlan_members):
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
        is_dict, keys = get_keys(port_ipv4)
        for port_key in keys:
            port_config = port_ipv4.get(port_key, {}) if is_dict else get_entry(port_ipv4, port_key)
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
                for ip in set(port_config["ips"].split(",")):
                    ip_address = ipaddress.ip_address(ip)
                    # Loop the IP of the dhcp interface and find the network that target ip is in this network.
                    self.match_range_network(dhcp_interface, dhcp_interface_name, port, [ip_address, ip_address])
            if "ranges" in port_config and len(port_config["ranges"]) != 0:
                for range_name in set(port_config["ranges"] if is_dict else port_config["ranges"].split(",")):
                    if range_name not in self.ranges:
                        syslog.syslog(syslog.LOG_WARNING, f"Range {range_name} is not in range table, skip")
                        continue
                    range = self.ranges[range_name]
                    # Loop the IP of the dhcp interface and find the network that target range is in this network.
                    self.match_range_network(dhcp_interface, dhcp_interface_name, port, range)
        # Merge ranges to avoid overlap
        for dhcp_interface_name, value in self.port_ips.items():
            for dhcp_interface_ip, port_range in value.items():
                for port_name, ip_range in port_range.items():
                    self.port_ips[dhcp_interface_name][dhcp_interface_ip][port_name] = merge_intervals(ip_range)

        ip_ports = {}
        for key, value in self.ip_ports.items():
            ip_ports[str(key)] = value
        try:
            # Store network - dhcp port map file which would be used by dhcpservd while updating lease table
            with open(DHCP_SERVER_IP_PORTS_FILE, "w") as write_file:
                json.dump(ip_ports, write_file, indent=4, ensure_ascii=False)
        except FileNotFoundError:
            syslog.syslog(syslog.LOG_ERR, "Cannot write to: {}".format(DHCP_SERVER_IP_PORTS_FILE))

    def generate_kea_dhcp4_config(self, from_db=True, config_file_path=""):
        """
        Generate kea-dhcp4 config
        Args:
            from_db: boolean, if set to True, generate config from running config_db
            config_file_path: str, if from_db is False, generate config from config_db file
        Returns:
            config dict
        """
        try:
            with open(INIT_CONFIG_FILE, "r", encoding="utf8")as fp:
                self.kea_config = json.load(fp)
        except FileNotFoundError:
            syslog.syslog(syslog.LOG_ERR, "Cannot find init config file {}".format(INIT_CONFIG_FILE))
            return None
        except json.decoder.JSONDecodeError:
            syslog.syslog(syslog.LOG_ERR, "Incorrect format of {}".format(INIT_CONFIG_FILE))
            return None

        # Generate from running config_db
        if from_db:
            self.db_connector = DhcpDbConnector()
            # Get host name
            device_metadata = self.db_connector.get_config_db_table("DEVICE_METADATA")
            localhost_entry = get_entry(device_metadata, "localhost")
            if localhost_entry is None or "hostname" not in localhost_entry:
                syslog.syslog(syslog.LOG_ERR, "Cannot get hostname")
                return None
            hostname = localhost_entry["hostname"]
            # Get ip information of vlan
            vlan_interface = self.db_connector.get_config_db_table("VLAN_INTERFACE")
            vlan_interface_keys = vlan_interface.getKeys()
            vlan_interfaces = self.get_vlan_ipv4_interface(vlan_interface_keys)
            dhcp_server_ipv4, customized_options_ipv4, range_ipv4, port_ipv4 = self.get_dhcp_ipv4_tables_from_db()
            vlan_member_table = self.db_connector.get_config_db_table("VLAN_MEMBER")
            vlan_members = vlan_member_table.getKeys()
        # Generate from config_db file
        else:
            try:
                with open(config_file_path, "r", encoding="utf8")as fp:
                    json_data = json.load(fp)
                    device_metadata = json_data.get("DEVICE_METADATA", {})
                    if "localhost" not in device_metadata or \
                       "hostname" not in device_metadata["localhost"]:
                        syslog.syslog(syslog.LOG_ERR, "Cannot get hostname")
                        return None
                    hostname = device_metadata["localhost"]["hostname"]
                    vlan_interface_keys = json_data.get("VLAN_INTERFACE", {}).keys()
                    vlan_interfaces = self.get_vlan_ipv4_interface(vlan_interface_keys)
                    dhcp_server_ipv4 = json_data.get(DHCP_SERVER_IPV4, {})
                    customized_options_ipv4 = json_data.get(DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS, {})
                    range_ipv4 = json_data.get(DHCP_SERVER_IPV4_RANGE, {})
                    port_ipv4 = json_data.get(DHCP_SERVER_IPV4_PORT, {})
                    vlan_members = list(json_data.get("VLAN_MEMBER", {}).keys())
            except FileNotFoundError:
                syslog.syslog(syslog.LOG_ERR, "Cannot find config_db file {}".format(config_file_path))
                return None
            except json.decoder.JSONDecodeError:
                syslog.syslog(syslog.LOG_ERR, "Incorrect format of {}".format(config_file_path))
                return None

        # Generate client class, this class is to classify packets from different physical interfaces
        client_class = self.generate_relay_client_class(hostname)
        # Parse range table
        self.parse_range(range_ipv4)

        # Parse customized options table
        self.parse_customized_options(customized_options_ipv4)

        # Parse port table
        self.parse_port(port_ipv4, vlan_interfaces, vlan_members)

        class_set = []
        classes_port = client_class.keys()
        # Construct config
        is_dict, keys = get_keys(dhcp_server_ipv4)
        for dhcp_key in keys:
            dhcp_server_entry = dhcp_server_ipv4.get(dhcp_key, {}) if is_dict else \
                get_entry(dhcp_server_ipv4, dhcp_key)
            if dhcp_server_entry is None:
                syslog.syslog(syslog.LOG_WARNING, f"Unable to get {dhcp_key} entry")
                continue
            # Skip non-enabled interface
            if "state" not in dhcp_server_entry or dhcp_server_entry["state"] != "enabled":
                syslog.syslog(syslog.LOG_INFO, f"DHCP Server state for {dhcp_key} is not enabled, skip")
                continue
            if "mode" not in dhcp_server_entry:
                syslog.syslog(syslog.LOG_WARNING, f"Missing dhcp mode setting for {dhcp_key}")
            if dhcp_server_entry["mode"] == "PORT":
                if dhcp_key not in vlan_interfaces:
                    syslog.syslog(syslog.LOG_INFO, f"Cannot find interface IP for {dhcp_key}, skip")
                for dhcp_interface_ip, ports in self.port_ips[dhcp_key].items():
                    # Specify server id via option 54 of DHCP reply packet
                    server_id = dhcp_interface_ip.split("/")[0]
                    # Sepcify address lease time via option 51 of DHCP reply packet
                    lease_time = int(dhcp_server_entry["lease_time"]) \
                        if "lease_time" in dhcp_server_entry else DEFAULT_LEASE_TIME
                    # Sepcify router ip via option 3 of DHCP reply packet
                    gateway = dhcp_server_entry["gateway"] if "gateway" in dhcp_server_entry else server_id
                    config_subnet = {
                        "subnet": str(ipaddress.ip_network(dhcp_interface_ip, False)),
                        "pools": [],
                        "option-data": [
                            {
                                "name": "routers",
                                "data": "{}".format(gateway)
                            },
                            {
                                "name": "dhcp-server-identifier",
                                "data": "{}".format(server_id)
                            }
                        ],
                        "valid-lifetime": lease_time,
                        "reservations": []
                    }
                    # Construct ip pools based on ip range.
                    for port_name, ip_ranges in ports.items():
                        if port_name in classes_port:
                            class_set.append(client_class[port_name])
                        for ip_range in ip_ranges:
                            pool = {
                                "pool": "{} - {}".format(str(ip_range[0]), str(ip_range[1])),
                                "client-class": "{}:{}".format(hostname, port_name)
                            }
                            config_subnet["pools"].append(pool)
                    # TODO Add customized options
                    self.kea_config["Dhcp4"]["subnet4"].append(config_subnet)
        if len(class_set) != 0:
            self.kea_config["Dhcp4"]["client-classes"] = class_set
        return self.kea_config


def main():
    dhcpservcfg = DhcpServCfg()
    dhcpservcfg.generate_kea_dhcp4_config(True, "/etc/sonic/config_db.json")


if __name__ == "__main__":
    main()
