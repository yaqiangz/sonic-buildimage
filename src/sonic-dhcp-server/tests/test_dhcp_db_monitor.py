import json
import pytest
from common_utils import MockSubscribeTable
from dhcp_server.common.dhcp_db_monitor import DhcpRelaydDbMonitor, DhcpServdDbMonitor, _DbEventExecutor
from dhcp_server.common.utils import DhcpDbConnector
from swsscommon import swsscommon
from unittest.mock import patch, call, ANY, PropertyMock

TEST_DATA_PATH = "tests/test_data/dhcp_db_monitor_test_data.json"
DHCP_SERVD_CHECK_PARAM = [
    {},
    {"enabled_dhcp_interfaces": "dummy1"},
    {"used_range": "dummy2"},
    {"Used_options": "dummy3"},
    {"enabled_dhcp_interfaces": "dummy1", "used_range": "dummy2"},
    {"enabled_dhcp_interfaces": "dummy1", "used_range": "dummy2", "used_options": "dummy3"}
]


def get_tested_data(test_name):
    test_obj = {}
    with open(TEST_DATA_PATH, "r") as file:
        test_obj = json.loads(file.read())
    tested_data = test_obj[test_name]
    for data in tested_data:
        for i in range(len(data["table"])):
            for j in range(len(data["table"][i][2])):
                data["table"][i][2][j] = tuple(data["table"][i][2][j])
            data["table"][i][2] = tuple(data["table"][i][2])
            data["table"][i] = tuple(data["table"][i])
    return tested_data


@pytest.mark.parametrize("tested_data", [get_tested_data("test_vlan_intf_update"),
                                         get_tested_data("test_pop_db_update_empty")])
def test_db_event_executor_pop_db_update_event(mock_swsscommon_dbconnector_init, tested_data):
    subscribe_vlan_table = MockSubscribeTable(tested_data[0]["table"])
    db_event_executor = _DbEventExecutor()
    db_event_executor.pop_db_update_event(subscribe_vlan_table)
    assert not subscribe_vlan_table.hasData()


@pytest.mark.parametrize("tested_data", get_tested_data("test_vlan_update"))
def test_db_event_executor_check_vlan_update(tested_data):
    subscribe_vlan_table = MockSubscribeTable(tested_data["table"])
    db_event_executor = _DbEventExecutor()
    check_res = db_event_executor.check_vlan_update(set(["Vlan1000"]), subscribe_vlan_table)
    assert check_res == tested_data["exp_res"]
    assert not subscribe_vlan_table.hasData()


@pytest.mark.parametrize("tested_data", get_tested_data("test_vlan_intf_update"))
def test_db_event_executor_check_vlan_intf_update(tested_data):
    subscribe_vlan_intf_table = MockSubscribeTable(tested_data["table"])
    db_event_executor = _DbEventExecutor()
    check_res = db_event_executor.check_vlan_intf_update(set(["Vlan1000"]), subscribe_vlan_intf_table)
    assert check_res == tested_data["exp_res"]
    assert not subscribe_vlan_intf_table.hasData()


@pytest.mark.parametrize("tested_class", ["dhcprelayd", "dhcpservd"])
def test_dhcp_relayd_servd_monitor_subscribe_table(mock_swsscommon_dbconnector_init, tested_class):
    with patch.object(swsscommon, "SubscriberStateTable", side_effect=mock_subscriber_state_table) as mock_subscribe, \
         patch.object(swsscommon.Select, "addSelectable", return_value=None) as mock_add_select:
        db_connector = DhcpDbConnector()
        db_monitor = DhcpRelaydDbMonitor(db_connector) if tested_class == "dhcprelayd" else \
            DhcpServdDbMonitor(db_connector)
        db_monitor.subscribe_table()
        calls_sub = [
            call(ANY, "DHCP_SERVER_IPV4"),
            call(ANY, "VLAN"),
            call(ANY, "VLAN_INTERFACE")
        ]
        calls_add_select = [
            call("DHCP_SERVER_IPV4"),
            call("VLAN"),
            call("VLAN_INTERFACE")
        ]
        if tested_class == "dhcpservd":
            calls_sub += [
                call(ANY, "DHCP_SERVER_IPV4_PORT"),
                call(ANY, "VLAN_MEMBER"),
                call(ANY, "DHCP_SERVER_IPV4_RANGE")
            ]
            calls_add_select += [
                call("DHCP_SERVER_IPV4_PORT"),
                call("VLAN_MEMBER"),
                call("DHCP_SERVER_IPV4_RANGE")
            ]
        mock_subscribe.assert_has_calls(calls_sub, any_order=True)
        mock_add_select.assert_has_calls(calls_add_select, any_order=True)


@pytest.mark.parametrize("select_result", [swsscommon.Select.TIMEOUT, swsscommon.Select.OBJECT])
def test_dhcp_relayd_monitor_check_db_update(mock_swsscommon_dbconnector_init, select_result):
    with patch.object(DhcpRelaydDbMonitor, "_check_dhcp_server_update") as mock_check_dhcp_server_update, \
         patch.object(_DbEventExecutor, "check_vlan_update") as mock_check_vlan_update, \
         patch.object(_DbEventExecutor, "pop_db_update_event") as mock_pop_db_update_event, \
         patch.object(_DbEventExecutor, "check_vlan_intf_update") as mock_check_vlan_intf_update, \
         patch.object(swsscommon.Select, "select", return_value=(select_result, None)):
        db_connector = DhcpDbConnector()
        dhcp_relayd_db_monitor = DhcpRelaydDbMonitor(db_connector)
        dhcp_relayd_db_monitor.check_db_update("dummy")
        if select_result == swsscommon.Select.OBJECT:
            mock_check_dhcp_server_update.assert_called_once_with("dummy")
            mock_check_vlan_update.assert_called_once_with("dummy", ANY)
            mock_check_vlan_intf_update.assert_called_once_with("dummy", ANY)
            mock_pop_db_update_event.assert_not_called()
        else:
            mock_check_dhcp_server_update.assert_not_called()
            mock_check_vlan_update.assert_not_called()
            mock_check_vlan_intf_update.assert_not_called()


@pytest.mark.parametrize("tested_data", get_tested_data("test_dhcp_server_update"))
@pytest.mark.parametrize("tested_class", ["dhcprelayd", "dhcpservd"])
def test_dhcp_relayd_servd_monitor_check_dhcp_server_update(mock_swsscommon_dbconnector_init, tested_data,
                                                            tested_class):
    with patch.object(DhcpRelaydDbMonitor if tested_class == "dhcprelayd" else DhcpServdDbMonitor,
                      "subscribe_dhcp_server_table", return_value=MockSubscribeTable(tested_data["table"]),
                      new_callable=PropertyMock):
        db_connector = DhcpDbConnector()
        dhcp_relayd_db_monitor = DhcpRelaydDbMonitor(db_connector) if tested_class == "dhcprelayd" else \
            DhcpServdDbMonitor(db_connector)
        check_res = dhcp_relayd_db_monitor._check_dhcp_server_update(set(["Vlan1000"]))
        exp_res = tested_data["exp_res"] if isinstance(tested_data["exp_res"], bool) else \
            tested_data["exp_res"][tested_class]
        assert check_res == exp_res


@pytest.mark.parametrize("select_result", [swsscommon.Select.TIMEOUT, swsscommon.Select.OBJECT])
def test_dhcp_servd_monitor_check_db_update(mock_swsscommon_dbconnector_init, select_result):
    with patch.object(DhcpServdDbMonitor, "_check_dhcp_server_update") as mock_check_dhcp_server_update, \
         patch.object(DhcpServdDbMonitor, "_check_dhcp_server_port_update") as mock_check_dhcp_server_port_update, \
         patch.object(DhcpServdDbMonitor, "_check_dhcp_server_range_update") as mock_check_dhcp_server_range_update, \
         patch.object(DhcpServdDbMonitor, "_check_dhcp_server_option_update") as mock_check_dhcp_server_option_update, \
         patch.object(DhcpServdDbMonitor, "_check_vlan_member_update") as mock_check_vlan_member_update, \
         patch.object(_DbEventExecutor, "check_vlan_update") as mock_check_vlan_update, \
         patch.object(_DbEventExecutor, "check_vlan_intf_update") as mock_check_vlan_intf_update, \
         patch.object(_DbEventExecutor, "pop_db_update_event"), \
         patch.object(swsscommon.Select, "select", return_value=(select_result, None)):
        db_connector = DhcpDbConnector()
        db_monitor = DhcpServdDbMonitor(db_connector)
        db_monitor.check_db_update("dummy1", "dummy2", "dummy3")
        if select_result == swsscommon.Select.OBJECT:
            mock_check_dhcp_server_update.assert_called_once_with("dummy1")
            mock_check_dhcp_server_port_update.assert_called_once_with("dummy1")
            mock_check_dhcp_server_range_update.assert_called_once_with("dummy2")
            mock_check_vlan_member_update.assert_called_once_with("dummy1")
            mock_check_dhcp_server_option_update.assert_called_once_with("dummy3"),
            mock_check_vlan_update.assert_called_once_with("dummy1", ANY),
            mock_check_vlan_intf_update.assert_called_once_with("dummy1", ANY)
        else:
            mock_check_dhcp_server_update.assert_not_called()
            mock_check_dhcp_server_port_update.assert_not_called()
            mock_check_dhcp_server_range_update.assert_not_called()
            mock_check_vlan_member_update.assert_not_called()
            mock_check_dhcp_server_option_update.assert_not_called()


@pytest.mark.parametrize("tested_data", get_tested_data("test_port_update"))
def test_dhcp_servd_monitor_check_dhcp_server_port_update(mock_swsscommon_dbconnector_init, tested_data):
    with patch.object(DhcpServdDbMonitor, "subscribe_dhcp_server_port_table",
                      return_value=MockSubscribeTable(tested_data["table"]), new_callable=PropertyMock):
        db_connector = DhcpDbConnector()
        dhcp_relayd_db_monitor = DhcpServdDbMonitor(db_connector)
        check_res = dhcp_relayd_db_monitor._check_dhcp_server_port_update(set(["Vlan1000"]))
        assert check_res == tested_data["exp_res"]


@pytest.mark.parametrize("tested_data", get_tested_data("test_option_update"))
def test_dhcp_servd_monitor_check_dhcp_server_option_update(mock_swsscommon_dbconnector_init, tested_data):
    with patch.object(DhcpServdDbMonitor, "subscribe_dhcp_server_options_table",
                      return_value=MockSubscribeTable(tested_data["table"]), new_callable=PropertyMock):
        db_connector = DhcpDbConnector()
        dhcp_relayd_db_monitor = DhcpServdDbMonitor(db_connector)
        check_res = dhcp_relayd_db_monitor._check_dhcp_server_option_update(set(["option223"]))
        assert check_res == tested_data["exp_res"]


@pytest.mark.parametrize("tested_data", get_tested_data("test_range_update"))
def test_dhcp_servd_monitor_check_dhcp_server_range_update(mock_swsscommon_dbconnector_init, tested_data):
    with patch.object(DhcpServdDbMonitor, "subscribe_dhcp_server_range_table",
                      return_value=MockSubscribeTable(tested_data["table"]), new_callable=PropertyMock):
        db_connector = DhcpDbConnector()
        dhcp_relayd_db_monitor = DhcpServdDbMonitor(db_connector)
        check_res = dhcp_relayd_db_monitor._check_dhcp_server_range_update(set(["range1"]))
        assert check_res == tested_data["exp_res"]


@pytest.mark.parametrize("tested_data", get_tested_data("test_vlan_member_update"))
def test_dhcp_servd_monitor_check_vlan_member_update(mock_swsscommon_dbconnector_init, tested_data):
    with patch.object(DhcpServdDbMonitor, "subscribe_vlan_member_table",
                      return_value=MockSubscribeTable(tested_data["table"]), new_callable=PropertyMock):
        db_connector = DhcpDbConnector()
        dhcp_relayd_db_monitor = DhcpServdDbMonitor(db_connector)
        check_res = dhcp_relayd_db_monitor._check_vlan_member_update(set(["Vlan1000"]))
        assert check_res == tested_data["exp_res"]


def mock_subscriber_state_table(db, table_name):
    return table_name
