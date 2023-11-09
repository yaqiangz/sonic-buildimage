import pytest
import sys
from common_utils import MockSubscribeTable, get_subscribe_table_tested_data, \
    PORT_MODE_SUBSCRIBE_TABLE, mock_exit_func
from dhcp_server.common.dhcp_db_monitor import DhcpRelaydDbMonitor, DhcpServdDbMonitor, ConfigDbEventChecker, \
    DhcpServerTableIntfEnablementEventChecker, DhcpServerTableCfgChangeEventChecker, \
    DhcpPortTableEventChecker, DhcpRangeTableEventChecker, DhcpOptionTableEventChecker, \
    VlanTableEventChecker, VlanMemberTableEventChecker, VlanIntfTableEventChecker
from dhcp_server.common.utils import DhcpDbConnector
from swsscommon import swsscommon
from unittest.mock import patch, ANY, PropertyMock, call, MagicMock


@pytest.mark.parametrize("select_result", [swsscommon.Select.TIMEOUT, swsscommon.Select.OBJECT])
def test_dhcp_relayd_monitor_check_db_update(mock_swsscommon_dbconnector_init, select_result):
    with patch.object(DhcpServerTableIntfEnablementEventChecker, "check_update_event") \
        as mock_check_update_event, \
         patch.object(VlanTableEventChecker, "check_update_event") as mock_check_vlan_update, \
         patch.object(VlanIntfTableEventChecker, "check_update_event") as mock_check_vlan_intf_update, \
         patch.object(swsscommon.Select, "select", return_value=(select_result, None)), \
         patch.object(ConfigDbEventChecker, "subscribe_table"):
        db_connector = DhcpDbConnector()
        dhcp_relayd_db_monitor = DhcpRelaydDbMonitor(db_connector)
        tested_db_snapshot = {"enabled_dhcp_interfaces": "dummy"}
        dhcp_relayd_db_monitor.check_db_update(tested_db_snapshot)
        if select_result == swsscommon.Select.OBJECT:
            mock_check_update_event.assert_called_once_with(tested_db_snapshot)
            mock_check_vlan_update.assert_called_once_with(tested_db_snapshot)
            mock_check_vlan_intf_update.assert_called_once_with(tested_db_snapshot)
        else:
            mock_check_update_event.assert_not_called()
            mock_check_vlan_update.assert_not_called()
            mock_check_vlan_intf_update.assert_not_called()


@pytest.mark.parametrize("tables", [["VLAN"], ["VLAN_MEMBER"]])
def test_dhcp_relayd_subscribe_tables(tables, mock_swsscommon_dbconnector_init):
    with patch.object(ConfigDbEventChecker, "subscribe_table") as mock_sub, \
         patch.object(sys, "exit", side_effect=mock_exit_func) as mock_exit:
        db_connector = DhcpDbConnector()
        dhcp_relayd_db_monitor = DhcpRelaydDbMonitor(db_connector)
        try:
            dhcp_relayd_db_monitor.subscribe_tables(set(tables))
        except SystemExit:
            mock_sub.assert_not_called()
            mock_exit.assert_called_once_with(1)
        else:
            mock_sub.assert_called_once()
            mock_exit.assert_not_called()


@pytest.mark.parametrize("select_result", [swsscommon.Select.TIMEOUT, swsscommon.Select.OBJECT])
def test_dhcp_servd_monitor_check_db_update(mock_swsscommon_dbconnector_init, select_result):
    with patch.object(DhcpServerTableCfgChangeEventChecker, "check_update_event") \
        as mock_check_dhcp_server_update_event, \
         patch.object(DhcpPortTableEventChecker, "check_update_event") as mock_check_dhcp_server_port_update, \
         patch.object(DhcpRangeTableEventChecker, "check_update_event") as mock_check_dhcp_server_range_update, \
         patch.object(DhcpOptionTableEventChecker, "check_update_event") as mock_check_dhcp_server_option_update, \
         patch.object(VlanMemberTableEventChecker, "check_update_event") as mock_check_vlan_member_update, \
         patch.object(VlanTableEventChecker, "check_update_event") as mock_check_vlan_update, \
         patch.object(VlanIntfTableEventChecker, "check_update_event") as mock_check_vlan_intf_update, \
         patch.object(swsscommon.Select, "select", return_value=(select_result, None)), \
         patch.object(DhcpServdDbMonitor, "subscribed_table", return_value=set(["DHCP_SERVER_IPV4", "VLAN"]),
                      new_callable=PropertyMock):
        db_connector = DhcpDbConnector()
        db_monitor = DhcpServdDbMonitor(db_connector)
        tested_db_snapshot = {"enabled_dhcp_interfaces": "dummy1", "used_range": "dummy2",
                              "used_options": "dummy3"}
        db_monitor.check_db_update(tested_db_snapshot)
        if select_result == swsscommon.Select.OBJECT:
            mock_check_dhcp_server_update_event.assert_called_once_with(tested_db_snapshot)
            mock_check_dhcp_server_port_update.assert_not_called()
            mock_check_dhcp_server_range_update.assert_not_called()
            mock_check_vlan_member_update.assert_not_called()
            mock_check_dhcp_server_option_update.assert_not_called()
            mock_check_vlan_update.assert_called_once_with(tested_db_snapshot)
            mock_check_vlan_intf_update.assert_not_called()
        else:
            mock_check_dhcp_server_update_event.assert_not_called()
            mock_check_dhcp_server_port_update.assert_not_called()
            mock_check_dhcp_server_range_update.assert_not_called()
            mock_check_vlan_member_update.assert_not_called()
            mock_check_dhcp_server_option_update.assert_not_called()
            mock_check_vlan_update.assert_not_called()
            mock_check_vlan_intf_update.assert_not_called()


@pytest.mark.parametrize("tables", [set(["dummy"]), set("dumm1")])
def test_dhcp_servd_monitor_subscribe_tables(mock_swsscommon_dbconnector_init, tables):
    with patch.object(sys, "exit", side_effect=mock_exit_func) as mock_exit, \
         patch.object(ConfigDbEventChecker, "subscribe_table") as mock_sub, \
         patch.object(DhcpServdDbMonitor, "checker_dict", return_value={"dummy": ConfigDbEventChecker(None)},
                      new_callable=PropertyMock):
        db_connector = DhcpDbConnector()
        db_monitor = DhcpServdDbMonitor(db_connector)
        try:
            db_monitor.subscribe_tables(tables)
        except SystemExit:
            mock_exit.assert_called_once_with(1)
        else:
            mock_exit.assert_not_called()
            mock_sub.assert_has_calls([
                call(ANY),
            ])


@pytest.mark.parametrize("tables", [set(PORT_MODE_SUBSCRIBE_TABLE), set(["dummy"])])
def test_dhcp_servd_monitor_unsubscribe_tables(mock_swsscommon_dbconnector_init, tables):
    with patch.object(sys, "exit", side_effect=mock_exit_func) as mock_exit, \
         patch.object(swsscommon.Select, "removeSelectable") as mock_remove:
        db_connector = DhcpDbConnector()
        db_monitor = DhcpServdDbMonitor(db_connector)
        try:
            db_monitor.unsubscribe_tables(tables)
        except SystemExit:
            mock_exit.assert_called_once_with(1)
            mock_remove.assert_not_called()
        else:
            mock_exit.assert_not_called()
            mock_remove.assert_has_calls([
                call("VLAN_MEMBER"),
                call("DHCP_SERVER_IPV4_RANGE"),
                call("VLAN_INTERFACE"),
                call("DHCP_SERVER_IPV4_PORT"),
                call("DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS"),
                call("DHCP_SERVER_IPV4"),
                call("VLAN")
            ], any_order=True)


def test_db_event_checker_init(mock_swsscommon_dbconnector_init):
    sel = swsscommon.Select()
    db_event_checker = ConfigDbEventChecker(sel)
    try:
        db_event_checker._get_parameter(None)
    except NotImplementedError:
        pass
    else:
        pytest.fail("Run _get_parameter didn't get error")
    try:
        db_event_checker._process_check(None, None, None, None)
    except NotImplementedError:
        pass
    else:
        pytest.fail("Run _process_check didn't get error")


@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_table_clear"))
def test_db_event_checker_clear_event(mock_swsscommon_dbconnector_init, tested_data):
    with patch.object(ConfigDbEventChecker, "subscribe_table"), \
         patch.object(ConfigDbEventChecker, "subscriber_state_table",
                      return_value=MockSubscribeTable(tested_data["table"]), new_callable=PropertyMock):
        sel = swsscommon.Select()
        db_event_checker = ConfigDbEventChecker(sel)
        db_event_checker.is_subscribed = True
        assert db_event_checker.subscriber_state_table.hasData()
        db_event_checker._clear_event()
        assert not db_event_checker.subscriber_state_table.hasData()


@pytest.mark.parametrize("param_name", ["param1", "param2"])
def test_db_event_checker_check_db_snapshot(mock_swsscommon_dbconnector_init, param_name):
    sel = swsscommon.Select()
    db_event_checker = ConfigDbEventChecker(sel)
    tested_db_snapshot = {"param1": "value1"}
    check_res = db_event_checker._check_db_snapshot(tested_db_snapshot, param_name)
    assert check_res == (param_name in tested_db_snapshot)


@pytest.mark.parametrize("is_subscribed", [True, False])
def test_db_event_checker_remove_subscribe(mock_swsscommon_dbconnector_init, is_subscribed):
    with patch.object(swsscommon.Select, "removeSelectable") as mock_remove, \
         patch.object(ConfigDbEventChecker, "is_subscribed", return_value=is_subscribed, new_callable=PropertyMock), \
         patch.object(sys, "exit", side_effect=mock_exit_func) as mock_exit:
        sel = swsscommon.Select()
        db_event_checker = ConfigDbEventChecker(sel)
        try:
            db_event_checker.remove_subscribe()
        except SystemExit:
            mock_remove.assert_not_called()
            mock_exit.assert_called_once_with(1)
        else:
            mock_remove.assert_called_once_with(None)
            mock_exit.assert_not_called()


@pytest.mark.parametrize("is_subscribed", [True, False])
def test_db_event_checker_subscribe_table(mock_swsscommon_dbconnector_init, is_subscribed):
    with patch.object(ConfigDbEventChecker, "is_subscribed", return_value=is_subscribed, new_callable=PropertyMock), \
         patch.object(sys, "exit", side_effect=mock_exit_func) as mock_exit, \
         patch.object(swsscommon, "SubscriberStateTable") as mock_sub, \
         patch.object(swsscommon.Select, "addSelectable") as mock_add_sel_tbl:
        sel = swsscommon.Select()
        db_event_checker = ConfigDbEventChecker(sel)
        try:
            db_event_checker.subscribe_table(MagicMock())
        except SystemExit:
            mock_exit.assert_called_once_with(1)
            mock_add_sel_tbl.assert_not_called()
            mock_sub.assert_not_called()
        else:
            mock_exit.assert_not_called()
            mock_add_sel_tbl.assert_called_once_with(ANY)
            mock_sub.assert_called_once_with(ANY, "")


@pytest.mark.parametrize("tested_db_snapshot", [{"enabled_dhcp_interfaces": "Vlan1000"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_dhcp_server_update"))
@pytest.mark.parametrize("is_subscribed", [True, False])
def test_dhcp_server_table_cfg_change_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot,
                                              is_subscribed):
    with patch.object(ConfigDbEventChecker, "subscribe_table"), \
         patch.object(ConfigDbEventChecker, "subscriber_state_table",
                      return_value=MockSubscribeTable(tested_data["table"]), new_callable=PropertyMock), \
         patch.object(ConfigDbEventChecker, "is_subscribed", return_value=is_subscribed, new_callable=PropertyMock), \
         patch.object(sys, "exit"):
        sel = swsscommon.Select()
        db_event_checker = DhcpServerTableCfgChangeEventChecker(sel)
        expected_res = tested_data["exp_res"] if isinstance(tested_data["exp_res"], bool) else \
            tested_data["exp_res"]["cfg_change"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "enabled_dhcp_interfaces" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res


@pytest.mark.parametrize("tested_db_snapshot", [{"enabled_dhcp_interfaces": "Vlan1000"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_dhcp_server_update"))
@pytest.mark.parametrize("is_subscribed", [True, False])
def test_dhcp_server_table_enablement_change_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot,
                                                     is_subscribed):
    with patch.object(ConfigDbEventChecker, "subscribe_table"), \
         patch.object(ConfigDbEventChecker, "subscriber_state_table",
                      return_value=MockSubscribeTable(tested_data["table"]), new_callable=PropertyMock), \
         patch.object(ConfigDbEventChecker, "is_subscribed", return_value=is_subscribed, new_callable=PropertyMock), \
         patch.object(sys, "exit"):
        sel = swsscommon.Select()
        db_event_checker = DhcpServerTableIntfEnablementEventChecker(sel)
        expected_res = tested_data["exp_res"] if isinstance(tested_data["exp_res"], bool) else \
            tested_data["exp_res"]["enablement"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "enabled_dhcp_interfaces" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res


@pytest.mark.parametrize("tested_db_snapshot", [{"enabled_dhcp_interfaces": "Vlan1000"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_port_update"))
@pytest.mark.parametrize("is_subscribed", [True, False])
def test_dhcp_port_table_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot, is_subscribed):
    with patch.object(ConfigDbEventChecker, "subscribe_table"), \
         patch.object(ConfigDbEventChecker, "subscriber_state_table",
                      return_value=MockSubscribeTable(tested_data["table"]), new_callable=PropertyMock), \
         patch.object(ConfigDbEventChecker, "is_subscribed", return_value=is_subscribed, new_callable=PropertyMock), \
         patch.object(sys, "exit"):
        sel = swsscommon.Select()
        db_event_checker = DhcpPortTableEventChecker(sel)
        expected_res = tested_data["exp_res"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "enabled_dhcp_interfaces" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res


@pytest.mark.parametrize("tested_db_snapshot", [{"used_range": "range1"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_range_update"))
@pytest.mark.parametrize("is_subscribed", [True, False])
def test_dhcp_range_table_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot, is_subscribed):
    with patch.object(ConfigDbEventChecker, "subscribe_table"), \
         patch.object(ConfigDbEventChecker, "subscriber_state_table",
                      return_value=MockSubscribeTable(tested_data["table"]), new_callable=PropertyMock), \
         patch.object(ConfigDbEventChecker, "is_subscribed", return_value=is_subscribed, new_callable=PropertyMock), \
         patch.object(sys, "exit"):
        sel = swsscommon.Select()
        db_event_checker = DhcpRangeTableEventChecker(sel)
        expected_res = tested_data["exp_res"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "used_range" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res


@pytest.mark.parametrize("tested_db_snapshot", [{"used_options": "option223"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_option_update"))
@pytest.mark.parametrize("is_subscribed", [True, False])
def test_dhcp_option_table_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot, is_subscribed):
    with patch.object(ConfigDbEventChecker, "subscribe_table"), \
         patch.object(ConfigDbEventChecker, "subscriber_state_table",
                      return_value=MockSubscribeTable(tested_data["table"]), new_callable=PropertyMock), \
         patch.object(ConfigDbEventChecker, "is_subscribed", return_value=is_subscribed, new_callable=PropertyMock), \
         patch.object(sys, "exit"):
        sel = swsscommon.Select()
        db_event_checker = DhcpOptionTableEventChecker(sel)
        expected_res = tested_data["exp_res"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "used_options" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res


@pytest.mark.parametrize("tested_db_snapshot", [{"enabled_dhcp_interfaces": "Vlan1000"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_vlan_update"))
@pytest.mark.parametrize("is_subscribed", [True, False])
def test_vlan_table_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot, is_subscribed):
    with patch.object(ConfigDbEventChecker, "subscribe_table"), \
         patch.object(ConfigDbEventChecker, "subscriber_state_table",
                      return_value=MockSubscribeTable(tested_data["table"]), new_callable=PropertyMock), \
         patch.object(ConfigDbEventChecker, "is_subscribed", return_value=is_subscribed, new_callable=PropertyMock), \
         patch.object(sys, "exit"):
        sel = swsscommon.Select()
        db_event_checker = VlanTableEventChecker(sel)
        expected_res = tested_data["exp_res"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "enabled_dhcp_interfaces" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res


@pytest.mark.parametrize("tested_db_snapshot", [{"enabled_dhcp_interfaces": "Vlan1000"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_vlan_intf_update"))
@pytest.mark.parametrize("is_subscribed", [True, False])
def test_vlan_intf_table_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot, is_subscribed):
    with patch.object(ConfigDbEventChecker, "subscribe_table"), \
         patch.object(ConfigDbEventChecker, "subscriber_state_table",
                      return_value=MockSubscribeTable(tested_data["table"]), new_callable=PropertyMock), \
         patch.object(ConfigDbEventChecker, "is_subscribed", return_value=is_subscribed, new_callable=PropertyMock), \
         patch.object(sys, "exit"):
        sel = swsscommon.Select()
        db_event_checker = VlanIntfTableEventChecker(sel)
        expected_res = tested_data["exp_res"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "enabled_dhcp_interfaces" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res


@pytest.mark.parametrize("tested_db_snapshot", [{"enabled_dhcp_interfaces": "Vlan1000"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_vlan_member_update"))
@pytest.mark.parametrize("is_subscribed", [True, False])
def test_vlan_member_table_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot, is_subscribed):
    with patch.object(ConfigDbEventChecker, "subscribe_table"), \
         patch.object(ConfigDbEventChecker, "subscriber_state_table",
                      return_value=MockSubscribeTable(tested_data["table"]), new_callable=PropertyMock), \
         patch.object(ConfigDbEventChecker, "is_subscribed", return_value=is_subscribed, new_callable=PropertyMock), \
         patch.object(sys, "exit"):
        sel = swsscommon.Select()
        db_event_checker = VlanMemberTableEventChecker(sel) 
        expected_res = tested_data["exp_res"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "enabled_dhcp_interfaces" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res
