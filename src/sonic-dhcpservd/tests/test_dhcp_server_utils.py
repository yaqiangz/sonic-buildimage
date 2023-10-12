import dhcpservd.dhcp_server_utils as dhcp_server_utils
import ipaddress
from swsscommon import swsscommon
from unittest.mock import patch, call, ANY


def test_construct_without_sock(mock_swsscommon_dbconnector_init):
    dhcp_server_utils.DhcpDbConnector()
    mock_swsscommon_dbconnector_init.assert_has_calls([
        call(swsscommon.CONFIG_DB, "127.0.0.1", 6379, 0),
        call(swsscommon.STATE_DB, "127.0.0.1", 6379, 0)
    ])


def test_construct_sock(mock_swsscommon_dbconnector_init):
    redis_sock = "/var/run/redis/redis.sock"
    dhcp_db_connector = dhcp_server_utils.DhcpDbConnector(redis_sock=redis_sock)
    assert dhcp_db_connector.redis_sock == redis_sock

    mock_swsscommon_dbconnector_init.assert_has_calls([
        call(swsscommon.CONFIG_DB, redis_sock, 0),
        call(swsscommon.STATE_DB, redis_sock, 0)
    ])


def test_get_config_db_table(mock_swsscommon_dbconnector_init, mock_swsscommon_table_init):
    dhcp_db_connector = dhcp_server_utils.DhcpDbConnector()
    with patch.object(swsscommon.Table, "getKeys", return_value=["key1", "key2"]) as mock_get_keys, \
         patch.object(dhcp_server_utils, "get_entry") as mock_get_entry:
        dhcp_db_connector.get_config_db_table("VLAN")
        mock_swsscommon_table_init.assert_called_once_with(dhcp_db_connector.config_db, "VLAN")
        mock_get_keys.assert_called_once_with()
        mock_get_entry.assert_has_calls([
            call(ANY, 'key1'),
            call().items(),
            call().items().__iter__(),
            call(ANY, 'key2'),
            call().items(),
            call().items().__iter__()
        ])


def test_merge_intervals():
    intervals = [
        [ipaddress.ip_address("192.168.0.2"), ipaddress.ip_address("192.168.0.5")],
        [ipaddress.ip_address("192.168.0.3"), ipaddress.ip_address("192.168.0.6")],
        [ipaddress.ip_address("192.168.0.10"), ipaddress.ip_address("192.168.0.10")]
    ]
    assert dhcp_server_utils.merge_intervals(intervals) == [
        [ipaddress.ip_address("192.168.0.2"), ipaddress.ip_address("192.168.0.6")],
        [ipaddress.ip_address("192.168.0.10"), ipaddress.ip_address("192.168.0.10")]
    ]
