import json
import pytest
from common_utils import MockSubscribeTable
from dhcp_server.common.dhcp_db_monitor import DhcpDbMonitor, DhcpRelaydDbMonitor, DhcpServdDbMonitor
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


@pytest.mark.parametrize("select_result", [swsscommon.Select.TIMEOUT, swsscommon.Select.OBJECT])
def test_dhcp_db_monitor(mock_swsscommon_dbconnector_init, select_result):
    db_connector = DhcpDbConnector()
    dhcp_db_monitor = DhcpDbMonitor(db_connector)
    try:
        dhcp_db_monitor.subscribe_table()
    except NotImplementedError:
        pass
    try:
        dhcp_db_monitor._do_check()
    except NotImplementedError:
        pass
    with patch.object(DhcpDbMonitor, "_do_check", return_value=None) as mock_do_check, \
         patch.object(swsscommon.Select, "select", return_value=(select_result, None)):
        dhcp_db_monitor.check_db_update("mock_param")
        if select_result == swsscommon.Select.TIMEOUT:
            mock_do_check.assert_not_called()
        elif select_result == swsscommon.Select.OBJECT:
            mock_do_check.assert_called_once_with("mock_param")


@pytest.mark.parametrize("tested_data", get_tested_data("test_vlan_update"))
def test_dhcp_db_monitor_check_vlan_update(mock_swsscommon_dbconnector_init, tested_data):
    with patch.object(DhcpDbMonitor, "subscribe_vlan_table", return_value=MockSubscribeTable(tested_data["table"]),
                      new_callable=PropertyMock):
        db_connector = DhcpDbConnector()
        dhcp_relayd_db_monitor = DhcpDbMonitor(db_connector)
        check_res = dhcp_relayd_db_monitor._check_vlan_update(set(["Vlan1000"]))
        assert check_res == tested_data["exp_res"]


@pytest.mark.parametrize("tested_data", get_tested_data("test_vlan_intf_update"))
def test_dhcp_db_monitor_check_vlan_intf_update(mock_swsscommon_dbconnector_init, tested_data):
    with patch.object(DhcpDbMonitor, "subscribe_vlan_intf_table", return_value=MockSubscribeTable(tested_data["table"]),
                      new_callable=PropertyMock):
        db_connector = DhcpDbConnector()
        dhcp_relayd_db_monitor = DhcpDbMonitor(db_connector)
        check_res = dhcp_relayd_db_monitor._check_vlan_intf_update(set(["Vlan1000"]))
        assert check_res == tested_data["exp_res"]


@pytest.mark.parametrize("tested_data", [get_tested_data("test_vlan_intf_update"),
                                         get_tested_data("test_pop_db_update_empty")])
def test_dhcp_db_monitor_pop_db_update_event(mock_swsscommon_dbconnector_init, tested_data):
    db_connector = DhcpDbConnector()
    dhcp_relayd_db_monitor = DhcpDbMonitor(db_connector)
    mock_sub_table = MockSubscribeTable(tested_data[0]["table"])
    dhcp_relayd_db_monitor._pop_db_update_event(mock_sub_table)
    assert not mock_sub_table.hasData()


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


@pytest.mark.parametrize("check_param", [{}, {"enabled_dhcp_interfaces": "dummy"}])
def test_dhcp_relayd_monitor_do_check(mock_swsscommon_dbconnector_init, check_param):
    with patch.object(DhcpRelaydDbMonitor, "_check_dhcp_server_update") as mock_check_dhcp_server_update, \
         patch.object(DhcpRelaydDbMonitor, "_check_vlan_update") as mock_check_vlan_update, \
         patch.object(DhcpRelaydDbMonitor, "_pop_db_update_event") as mock__pop_db_update_event, \
         patch.object(DhcpRelaydDbMonitor, "_check_vlan_intf_update") as mock_check_vlan_intf_update:
        db_connector = DhcpDbConnector()
        dhcp_relayd_db_monitor = DhcpRelaydDbMonitor(db_connector)
        dhcp_relayd_db_monitor._do_check(check_param)
        if "enabled_dhcp_interfaces" in check_param:
            mock_check_dhcp_server_update.assert_called_once_with("dummy")
            mock_check_vlan_update.assert_called_once_with("dummy")
            mock_check_vlan_intf_update.assert_called_once_with("dummy")
            mock__pop_db_update_event.assert_not_called()
        else:
            mock_check_dhcp_server_update.assert_not_called()
            mock_check_vlan_update.assert_not_called()
            mock_check_vlan_intf_update.assert_not_called()
            mock__pop_db_update_event.assert_has_calls([call(None) for _ in range(3)])


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


@pytest.mark.parametrize("check_param", DHCP_SERVD_CHECK_PARAM)
def test_dhcp_servd_monitor_do_check(mock_swsscommon_dbconnector_init, check_param):
    with patch.object(DhcpServdDbMonitor, "_check_dhcp_server_update") as mock_check_dhcp_server_update, \
         patch.object(DhcpServdDbMonitor, "_check_vlan_update") as mock_check_vlan_update, \
         patch.object(DhcpServdDbMonitor, "_check_vlan_intf_update") as mock_check_vlan_intf_update, \
         patch.object(DhcpServdDbMonitor, "_check_dhcp_server_port_update") as mock_check_dhcp_server_port_update, \
         patch.object(DhcpServdDbMonitor, "_check_dhcp_server_range_update") as mock_check_dhcp_server_range_update, \
         patch.object(DhcpServdDbMonitor, "_check_dhcp_server_option_update") as mock_check_dhcp_server_option_update, \
         patch.object(DhcpServdDbMonitor, "_pop_db_update_event") as mock_pop_db_update_event, \
         patch.object(DhcpServdDbMonitor, "_check_vlan_member_update") as mock_check_vlan_member_update:
        db_connector = DhcpDbConnector()
        db_monitor = DhcpServdDbMonitor(db_connector)
        db_monitor._do_check(check_param)
        if "enabled_dhcp_interfaces" in check_param and "used_range" in check_param and "used_options" in check_param:
            mock_check_dhcp_server_update.assert_called_once_with("dummy1")
            mock_check_vlan_update.assert_called_once_with("dummy1")
            mock_check_vlan_intf_update.assert_called_once_with("dummy1")
            mock_check_dhcp_server_port_update.assert_called_once_with("dummy1")
            mock_check_dhcp_server_range_update.assert_called_once_with("dummy2")
            mock_check_vlan_member_update.assert_called_once_with("dummy1")
            mock_check_dhcp_server_option_update.assert_called_once_with("dummy3")
            mock_pop_db_update_event.assert_not_called()
        else:
            mock_check_dhcp_server_update.assert_not_called()
            mock_check_vlan_update.assert_not_called()
            mock_check_vlan_intf_update.assert_not_called()
            mock_check_dhcp_server_port_update.assert_not_called()
            mock_check_dhcp_server_range_update.assert_not_called()
            mock_check_vlan_member_update.assert_not_called()
            mock_check_dhcp_server_option_update.assert_not_called()
            mock_pop_db_update_event.assert_has_calls([call(None) for _ in range(7)])


@pytest.mark.parametrize("tested_data", get_tested_data("test_port_update"))
def test_dhcp_servd_monitor_check_dhcp_server_port_update(mock_swsscommon_dbconnector_init, tested_data):
    with patch.object(DhcpServdDbMonitor, "subscribe_dhcp_server_port_table",
                      return_value=MockSubscribeTable(tested_data["table"]), new_callable=PropertyMock):
        db_connector = DhcpDbConnector()
        dhcp_relayd_db_monitor = DhcpServdDbMonitor(db_connector)
        check_res = dhcp_relayd_db_monitor._check_dhcp_server_port_update(set(["Vlan1000"]))
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
