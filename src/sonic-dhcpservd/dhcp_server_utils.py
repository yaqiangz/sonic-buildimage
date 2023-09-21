from swsscommon import swsscommon

REDIS_SOCK_PATH = "/var/run/redis/redis.sock"
LEASE_FILE_PATH = "/tmp/kea-lease.csv"
DHCP_SERVER_IPV4_LEASE = "DHCP_SERVER_IPV4_LEASE"
DHCP_SERVER_IP_PORTS_FILE = "/tmp/dhcp_server_ip_ports.json"
INIT_CONFIG_FILE = "/etc/kea/init_kea_dhcp4.conf"


class DhcpDbConnector(object):
    def __init__(self):
        self.redis_sock = REDIS_SOCK_PATH
        self.config_db = swsscommon.DBConnector(swsscommon.CONFIG_DB, self.redis_sock, 0)
        self.state_db = swsscommon.DBConnector(swsscommon.STATE_DB, self.redis_sock, 0)

    def get_config_db_table(self, table_name):
        """
        Get table from config_db.
        Args:
            table_name: Name of table want to get.
        Return:
            Table objects.
        """
        return swsscommon.Table(self.config_db, table_name)

    def get_state_db_table(self, table_name):
        """
        Get table from state_db.
        Args:
            table_name: Name of table want to get.
        Return:
            Table objects.
        """
        return swsscommon.Table(self.state_db, table_name)


def get_entry(table, entry_name):
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


def merge_intervals(intervals):
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


def get_keys(obj):
    """
    Get keys from config db table or db dict
    Args:
        obj: db table or dict
    Returns:
        is_dict: boolean, indicate whether obj is dict
        keys: list of keys
    """
    is_dict = True if isinstance(obj, dict) else False
    keys = list(obj.keys()) if is_dict else obj.getKeys()
    return is_dict, keys
