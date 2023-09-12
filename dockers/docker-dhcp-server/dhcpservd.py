import ipaddress
import json
import sys
import syslog
import signal
import time
import psutil
from collections import deque
from swsscommon import swsscommon

REDIS_SOCK_PATH = "/var/run/redis/redis.sock"
# Table name in config_db
DHCP_SERVER_IPV4 = "DHCP_SERVER_IPV4"
DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS = "DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS"
DHCP_SERVER_IPV4_RANGE = "DHCP_SERVER_IPV4_RANGE"
DHCP_SERVER_IPV4_PORT = "DHCP_SERVER_IPV4_PORT"
DHCP_SERVER_IPV4_LEASE = "DHCP_SERVER_IPV4_LEASE"
DEVICE_METADATA = "DEVICE_METADATA"
LEASE_FILE_PATH = "/tmp/kea-lease.csv"

# Default lease time of DHCP
DEFAULT_LEASE_TIME = 900
PORT_MAP_PATH = "/tmp/port-name-alias-map.txt"
# TODO: Remove this once we no longer support Python 2
if sys.version_info.major == 3:
    UNICODE_TYPE = str
else:
    UNICODE_TYPE = unicode
INIT_CONFIG = {
    "Dhcp4": {
        "hooks-libraries": [
            {
                "library": "/usr/local/lib/kea/hooks/libdhcp_run_script.so",
                "parameters": {
                    "name": "/etc/kea/lease_update.sh",
                    "sync": False
                }
            }
        ],
        "interfaces-config": {
            "interfaces": ["eth0"]
        },
        "control-socket": {
            "socket-type": "unix",
            "socket-name": "/run/kea/kea4-ctrl-socket"
        },
        "lease-database": {
            "type": "memfile",
            "persist": True,
            "name": LEASE_FILE_PATH,
            "lfc-interval": 3600
        },
        "subnet4": [],
        "loggers": [
            {
                "name": "kea-dhcp4",
                "output_options": [
                    {
                        "output": "/tmp/kea-dhcp.log",
                        "pattern": "%-5p %m\n"
                    }
                ],
                "severity": "INFO",
                "debuglevel": 0
            }
        ]
    }
}


class DhcpServd(object):
    def __init__(self):
        self.redis_sock = REDIS_SOCK_PATH
        self.config_db = swsscommon.DBConnector(swsscommon.CONFIG_DB, self.redis_sock, 0)
        self.state_db = swsscommon.DBConnector(swsscommon.STATE_DB, self.redis_sock, 0)
        self.port_alias_map = {}
        with open(PORT_MAP_PATH, "r") as file:
            lines = file.readlines()
            for line in lines:
                splits = line.strip().split(" ")
                if len(splits) != 2:
                    continue
                self.port_alias_map[splits[0]] = splits[1]

    def get_table(self, db, table_name):
        """
        Get table from db.
        Args:
            db: An db object.
            table_name: Name of table want to get.
        Return:
            Table objects.
        """
        return swsscommon.Table(db, table_name)

    def get_dhcp_ipv4_tables(self):
        """
        Get DHCP Server IPv4 related table from config_db.
        Returns:
            Four table objects.
        """
        dhcp_server_ipv4 = self.get_table(self.config_db, DHCP_SERVER_IPV4)
        customized_options_ipv4 = self.get_table(self.config_db, DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS)
        range_ipv4 = self.get_table(self.config_db, DHCP_SERVER_IPV4_RANGE)
        port_ipv4 = self.get_table(self.config_db, DHCP_SERVER_IPV4_PORT)
        return dhcp_server_ipv4, customized_options_ipv4, range_ipv4, port_ipv4

    def get_entry(self, table, entry_name):
        """
        Get dict entry from Table object.
        Args:
            table: Table object.
            entry_name: Name of entry.
        Returns:
            Dict of entry, sample:
                {
                    "customized_options": "option60,option223",
                    "gateway": "192.168.0.1",
                    "lease_time": "900",
                    "mode": "PORT",
                    "netmask": "255.255.255.0",
                    "state": "enabled"
                }
        """
        (status, entry) = table.get(entry_name)
        if not status:
            return None
        return dict(entry)

    def generate_relay_client_class(self, hostname):
        """
        Generate client class to classify requests from different physical interfaces, which is the base of ip
        assigning.
        Args:
            hostname: Host name of current device.
        Returns:
            Dict of lient_class dict, sample:
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

    def get_vlan_ipv4_interface(self):
        """
        Get ipv4 info of vlans
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
        vlan_interface = self.get_table(self.config_db, "VLAN_INTERFACE")
        vlan_interface_keys = vlan_interface.getKeys()
        for key in vlan_interface_keys:
            splits = key.split("|")
            if len(splits) != 2:
                continue
            network = ipaddress.ip_network(UNICODE_TYPE(splits[1]), False)
            if network.version != 4:
                continue
            if key not in ret:
                ret[splits[0]] = []
            ret[splits[0]].append({"network": network, "ip": splits[1]})
        return ret

    def merge_intervals(self, intervals):
        """
        Merge ip range intervals.
        Args:
            intervals: Ip ranges, may have overlaps, sample:
                [
                    [IPv4Address('192.168.0.2'), IPv4Address('192.168.0.5')],
                    [IPv4Address('192.168.0.3'), IPv4Address('192.168.0.6')],
                    [IPv4Address('192.168.0.10'), IPv4Address('192.168.0.10')]
                ]
        Returns:
            Merged ip ranges, sample:
                [
                    [IPv4Address('192.168.0.2'), IPv4Address('192.168.0.6')],
                    [IPv4Address('192.168.0.10'), IPv4Address('192.168.0.10')]
                ]
        """
        intervals.sort(key=lambda x: x[0])
        ret = []
        for interval in intervals:
            if len(ret) == 0 or interval[0] > ret[-1][-1]:
                ret.append(interval)
            else:
                ret[-1][-1] = max(ret[-1][-1], interval[-1])
        return ret

    def ip_in_net(self, ip, network):
        """
        Check whether ip address in network.
        Args:
            ip: Ip address.
            network: Target network.
        Returns:
            Flag:
                True - Ip is in network.
                False - Ip is not in network.
        """
        return ip in network

    def parse_range(self, range_ipv4):
        """
        Parse content in DHCP_SERVER_IPV4_RANGE table to below format:
        {
            'range2': [IPv4Address('192.168.0.3'), IPv4Address('192.168.0.6')],
            'range1': [IPv4Address('192.168.0.2'), IPv4Address('192.168.0.5')],
            'range3': [IPv4Address('192.168.0.10'), IPv4Address('192.168.0.10')]
        }
        Args:
            range_ipv4: Table object.
        """
        self.ranges = {}
        for range in range_ipv4.getKeys():
            range_entry = self.get_entry(range_ipv4, range)
            splits = range_entry["range"].split(",")
            if len(splits) != 2:
                continue
            address_1 = ipaddress.ip_address(splits[0])
            address_2 = ipaddress.ip_address(splits[1])
            # To make sure order of range is correct
            range_start = address_1 if address_1 < address_2 else address_2
            range_end = address_2 if address_1 < address_2 else address_1
            self.ranges[range] = [range_start, range_end]

    def parse_customized_options(self, customized_options_ipv4):
        """
        Parse content in DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS table.
        Args:
            customized_options_ipv4: Table object.
        """
        # TODO validate option type
        self.customized_options = {}
        for option in customized_options_ipv4.getKeys():
            self.customized_options[option] = self.get_entry(customized_options_ipv4, option)

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
            if not self.ip_in_net(range[0], dhcp_interface_ip["network"]) or \
               not self.ip_in_net(range[1], dhcp_interface_ip["network"]):
                continue
            dhcp_interface_ip_str = dhcp_interface_ip["ip"]
            if dhcp_interface_ip_str not in self.port_ips[dhcp_interface_name]:
                self.port_ips[dhcp_interface_name][dhcp_interface_ip_str] = {}
            if port not in self.port_ips[dhcp_interface_name][dhcp_interface_ip_str]:
                self.port_ips[dhcp_interface_name][dhcp_interface_ip_str][port] = []
            self.port_ips[dhcp_interface_name][dhcp_interface_ip_str][port].append([range[0], range[1]])
            break

    def parse_port(self, port_ipv4, vlan_interfaces):
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
            IPv4Network('192.168.0.0/24')
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
        for port_key in port_ipv4.getKeys():
            port_config = self.get_entry(port_ipv4, port_key)
            # Cannot specify both 'ips' and 'ranges'
            if "ips" in port_config and len(port_config["ips"]) != 0 and "ranges" in port_config \
               and len(port_config["ranges"]) != 0:
                syslog.syslog(syslog.LOG_WARNING, f"Port config for {port_key} contains both ips and ranges, skip")
                continue
            splits = port_key.split("|")
            # Get dhcp interface name like Vlan1000
            dhcp_interface_name = splits[0]
            # Get dhcp member interface name like etp1
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
                for range_name in set(port_config["ranges"].split(",")):
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
                    self.port_ips[dhcp_interface_name][dhcp_interface_ip][port_name] = self.merge_intervals(ip_range)

    def generate_kea_dhcp4_config(self):
        """
        Generate dhcp4 config.
        """
        self.kea_config = INIT_CONFIG


        # Get host name
        device_metadata = self.get_table(self.config_db, DEVICE_METADATA)
        localhost_entry = self.get_entry(device_metadata, "localhost")
        if localhost_entry is None or "hostname" not in localhost_entry:
            syslog.syslog(syslog.ERROR, "Cannot get hostname")
            return
        hostname = localhost_entry["hostname"]

        # Generate client class, this class is to classify packets from different physical interfaces
        client_class = self.generate_relay_client_class(hostname)

        # Get ip information of vlan
        vlan_interfaces = self.get_vlan_ipv4_interface()
        dhcp_server_ipv4, customized_options_ipv4, range_ipv4, port_ipv4 = self.get_dhcp_ipv4_tables()

        # Parse range table
        self.parse_range(range_ipv4)

        # Parse customized options table
        self.parse_customized_options(customized_options_ipv4)

        # Parse port table
        self.parse_port(port_ipv4, vlan_interfaces)

        class_set = []
        classes_port = client_class.keys()
        # Construct config
        for dhcp_key in dhcp_server_ipv4.getKeys():
            dhcp_server_entry = self.get_entry(dhcp_server_ipv4, dhcp_key)
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
        self.kea_config["Dhcp4"]["client-classes"] = class_set

        with open("/etc/kea/kea-dhcp4.conf", "w") as file:
            json.dump(self.kea_config, file, indent=4, ensure_ascii=False)

    def clear_table(self, db, table_name):
        """
        Clear table in db.
        Args:
            db: Db object.
            table_name: Name of table to be clear
        """
        for key in db.keys("{}*".format(table_name)):
            db.delete(key)

    def update_lease_handler(self, signum, frame):
        """
        Hanlder function to update lease table in STATE_DB
        """
        # Read lease file generated by kea-dhcp4
        lease_obj = {}
        with open(LEASE_FILE_PATH, "r", encoding="utf-8") as fb:
            dq = deque(fb)
        while dq:
            last_row = dq.pop()
            splits = last_row.split(",")
            if splits[0] == "address":
                break
            ip_str = splits[0]
            mac_address = splits[1]
            if mac_address in lease_obj:
                continue
            valid_lifetime = splits[3]
            lease_end = splits[4]
            lease_obj[mac_address] = {
                "lease_start": str(int(lease_end) - int(valid_lifetime)),
                "lease_end": lease_end,
                "ip": ip_str
            }
        # Clear lease table in STATE_DB
        self.clear_table(self.state_db, DHCP_SERVER_IPV4_LEASE)
        # Update lease table
        for mac_address, value in lease_obj.items():
            ip_str = value["ip"]
            if value["lease_start"] == value["lease_end"]:
                continue
            for net in self.ip_ports.keys():
                if self.ip_in_net(ipaddress.ip_address(ip_str), net):
                    key = "{}|{}|{}".format(DHCP_SERVER_IPV4_LEASE, self.ip_ports[net], mac_address)
                    for k, v in value.items():
                        self.state_db.hset(key, k, v)

    def add_signal_handler(self):
        """
        Add signal handler
        """
        # Listen SIGUSR1 to update lease table.
        signal.signal(signal.SIGUSR1, self.update_lease_handler)

    def sighup_process(self, process_name):
        for proc in psutil.process_iter():
            if process_name in proc.name():
                proc.send_signal(signal.SIGHUP)


if __name__ == "__main__":
    dhcpservd = DhcpServd()
    dhcpservd.generate_kea_dhcp4_config()
    dhcpservd.add_signal_handler()
    dhcpservd.sighup_process("kea-dhcp4")
    while True:
        time.sleep(5)
