from common_utils import mock_get_config_db_table
from dhcp_server.dhcp_server_utils import DhcpDbConnector
from dhcp_server.dhcprelayd import DhcpRelayd
from unittest.mock import patch, call, MagicMock


def test_start(mock_swsscommon_dbconnector_init):
    with patch.object(DhcpRelayd, "refresh_dhcrelay", return_value=None) as mock_refresh, \
         patch.object(DhcpRelayd, "_subscribe_config_db", return_value=None) as mock_subscribe:
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        dhcprelayd.start()
        mock_refresh.assert_called_once_with()
        mock_subscribe.assert_called_once_with()

def test_refresh_dhcrelay(mock_swsscommon_dbconnector_init):
    with patch.object(DhcpRelayd, "_get_dhcp_server_ip", return_value="240.127.1.2"), \
         patch.object(DhcpDbConnector, "get_config_db_table", side_effect=mock_get_config_db_table):
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        dhcprelayd.refresh_dhcrelay()


def test_wait():
    pass


def test_subscribe_config_db():
    pass


def test_config_db_update_event():
    pass


def test_dhcp_server_update_event():
    pass


def test_vlan_update_event():
    pass


def test_kill_exist_dhcrelay():
    pass


def test_get_dhcp_server_ip():
    pass
