import pytest
from common_utils import MockSubscribeTable, get_subscribe_table_tested_data
from dhcp_server.common.dhcp_db_monitor import DhcpRelaydDbMonitor, DhcpServdDbMonitor, DbEventChecker, \
                                               DhcpServerTableIntfEnablementEventChecker, \
                                               DhcpServerTableCfgChangeEventChecker, \
                                               DhcpPortTableEventChecker, \
                                               DhcpRangeTableEventChecker, \
                                               DhcpOptionTableEventChecker, \
                                               VlanTableEventChecker, \
                                               VlanMemberTableEventChecker, \
                                               VlanIntfTableEventChecker
from dhcp_server.common.utils import DhcpDbConnector
from swsscommon import swsscommon
from unittest.mock import patch, ANY, PropertyMock


@pytest.mark.parametrize("select_result", [swsscommon.Select.TIMEOUT, swsscommon.Select.OBJECT])
def test_dhcp_relayd_monitor_check_db_update(mock_swsscommon_dbconnector_init, select_result, mock_subscribe_table):
    with patch.object(DhcpServerTableIntfEnablementEventChecker, "check_update_event") \
        as mock_check_update_event, \
         patch.object(VlanTableEventChecker, "check_update_event") as mock_check_vlan_update, \
         patch.object(VlanIntfTableEventChecker, "check_update_event") as mock_check_vlan_intf_update, \
         patch.object(swsscommon.Select, "select", return_value=(select_result, None)):
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


@pytest.mark.parametrize("select_result", [swsscommon.Select.TIMEOUT, swsscommon.Select.OBJECT])
def test_dhcp_servd_monitor_check_db_update(mock_swsscommon_dbconnector_init, select_result, mock_subscribe_table):
    with patch.object(DhcpServerTableCfgChangeEventChecker, "check_update_event") \
        as mock_check_dhcp_server_update_event, \
         patch.object(DhcpPortTableEventChecker, "check_update_event") as mock_check_dhcp_server_port_update, \
         patch.object(DhcpRangeTableEventChecker, "check_update_event") as mock_check_dhcp_server_range_update, \
         patch.object(DhcpOptionTableEventChecker, "check_update_event") as mock_check_dhcp_server_option_update, \
         patch.object(VlanMemberTableEventChecker, "check_update_event") as mock_check_vlan_member_update, \
         patch.object(VlanTableEventChecker, "check_update_event") as mock_check_vlan_update, \
         patch.object(VlanIntfTableEventChecker, "check_update_event") as mock_check_vlan_intf_update, \
         patch.object(swsscommon.Select, "select", return_value=(select_result, None)):
        db_connector = DhcpDbConnector()
        db_monitor = DhcpServdDbMonitor(db_connector)
        tested_db_snapshot = {"enabled_dhcp_interfaces": "dummy1", "used_range": "dummy2",
                              "used_options": "dummy3"}
        db_monitor.check_db_update(tested_db_snapshot)
        if select_result == swsscommon.Select.OBJECT:
            mock_check_dhcp_server_update_event.assert_called_once_with(tested_db_snapshot)
            mock_check_dhcp_server_port_update.assert_called_once_with(tested_db_snapshot)
            mock_check_dhcp_server_range_update.assert_called_once_with(tested_db_snapshot)
            mock_check_vlan_member_update.assert_called_once_with(tested_db_snapshot)
            mock_check_dhcp_server_option_update.assert_called_once_with(tested_db_snapshot),
            mock_check_vlan_update.assert_called_once_with(tested_db_snapshot),
            mock_check_vlan_intf_update.assert_called_once_with(tested_db_snapshot)
        else:
            mock_check_dhcp_server_update_event.assert_not_called()
            mock_check_dhcp_server_port_update.assert_not_called()
            mock_check_dhcp_server_range_update.assert_not_called()
            mock_check_vlan_member_update.assert_not_called()
            mock_check_dhcp_server_option_update.assert_not_called()
            mock_check_vlan_update.assert_not_called()
            mock_check_vlan_intf_update.assert_not_called()


def test_db_event_checker_init(mock_swsscommon_dbconnector_init, mock_subscribe_table):
    sel = swsscommon.Select()
    db_connector = DhcpDbConnector()
    DbEventChecker(sel, db_connector)
    mock_subscribe, mock_add_select = mock_subscribe_table
    mock_subscribe.assert_called_once_with(ANY, "")
    mock_add_select.assert_called_once()


@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_table_clear"))
def test_db_event_checker_clear_event(mock_swsscommon_dbconnector_init, tested_data):
    with patch.object(DbEventChecker, "_subscribe_table"), \
         patch.object(DbEventChecker, "subscribe_table", return_value=MockSubscribeTable(tested_data["table"]),
                      new_callable=PropertyMock):
        sel = swsscommon.Select()
        db_connector = DhcpDbConnector()
        db_event_checker = DbEventChecker(sel, db_connector)
        assert db_event_checker.subscribe_table.hasData()
        db_event_checker._clear_event()
        assert not db_event_checker.subscribe_table.hasData()


@pytest.mark.parametrize("param_name", ["param1", "param2"])
def test_db_event_checker_check_db_snapshot(mock_swsscommon_dbconnector_init, param_name, mock_subscribe_table):
    sel = swsscommon.Select()
    db_connector = DhcpDbConnector()
    db_event_checker = DbEventChecker(sel, db_connector)
    tested_db_snapshot = {"param1": "value1"}
    check_res = db_event_checker._check_db_snapshot(tested_db_snapshot, param_name)
    assert check_res == (param_name in tested_db_snapshot)


def test_db_event_checker_check_update_event(mock_swsscommon_dbconnector_init, mock_subscribe_table):
    sel = swsscommon.Select()
    db_connector = DhcpDbConnector()
    db_event_checker = DbEventChecker(sel, db_connector)
    try:
        db_event_checker.check_update_event()
    except NotImplementedError:
        pass


@pytest.mark.parametrize("tested_db_snapshot", [{"enabled_dhcp_interfaces": "Vlan1000"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_dhcp_server_update"))
def test_dhcp_server_table_cfg_change_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot):
    with patch.object(DbEventChecker, "_subscribe_table"), \
         patch.object(DbEventChecker, "subscribe_table", return_value=MockSubscribeTable(tested_data["table"]),
                      new_callable=PropertyMock):
        sel = swsscommon.Select()
        db_connector = DhcpDbConnector()
        db_event_checker = DhcpServerTableCfgChangeEventChecker(sel, db_connector)
        expected_res = tested_data["exp_res"] if isinstance(tested_data["exp_res"], bool) else \
            tested_data["exp_res"]["cfg_change"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "enabled_dhcp_interfaces" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res


@pytest.mark.parametrize("tested_db_snapshot", [{"enabled_dhcp_interfaces": "Vlan1000"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_dhcp_server_update"))
def test_dhcp_server_table_enablement_change_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot):
    with patch.object(DbEventChecker, "_subscribe_table"), \
         patch.object(DbEventChecker, "subscribe_table", return_value=MockSubscribeTable(tested_data["table"]),
                      new_callable=PropertyMock):
        sel = swsscommon.Select()
        db_connector = DhcpDbConnector()
        db_event_checker = DhcpServerTableIntfEnablementEventChecker(sel, db_connector)
        expected_res = tested_data["exp_res"] if isinstance(tested_data["exp_res"], bool) else \
            tested_data["exp_res"]["enablement"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "enabled_dhcp_interfaces" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res


@pytest.mark.parametrize("tested_db_snapshot", [{"enabled_dhcp_interfaces": "Vlan1000"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_port_update"))
def test_dhcp_port_table_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot):
    with patch.object(DbEventChecker, "_subscribe_table"), \
         patch.object(DbEventChecker, "subscribe_table", return_value=MockSubscribeTable(tested_data["table"]),
                      new_callable=PropertyMock):
        sel = swsscommon.Select()
        db_connector = DhcpDbConnector()
        db_event_checker = DhcpPortTableEventChecker(sel, db_connector)
        expected_res = tested_data["exp_res"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "enabled_dhcp_interfaces" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res


@pytest.mark.parametrize("tested_db_snapshot", [{"used_range": "range1"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_range_update"))
def test_dhcp_range_table_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot):
    with patch.object(DbEventChecker, "_subscribe_table"), \
         patch.object(DbEventChecker, "subscribe_table", return_value=MockSubscribeTable(tested_data["table"]),
                      new_callable=PropertyMock):
        sel = swsscommon.Select()
        db_connector = DhcpDbConnector()
        db_event_checker = DhcpRangeTableEventChecker(sel, db_connector)
        expected_res = tested_data["exp_res"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "used_range" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res


@pytest.mark.parametrize("tested_db_snapshot", [{"used_options": "option223"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_option_update"))
def test_dhcp_option_table_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot):
    with patch.object(DbEventChecker, "_subscribe_table"), \
         patch.object(DbEventChecker, "subscribe_table", return_value=MockSubscribeTable(tested_data["table"]),
                      new_callable=PropertyMock):
        sel = swsscommon.Select()
        db_connector = DhcpDbConnector()
        db_event_checker = DhcpOptionTableEventChecker(sel, db_connector)
        expected_res = tested_data["exp_res"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "used_options" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res


@pytest.mark.parametrize("tested_db_snapshot", [{"enabled_dhcp_interfaces": "Vlan1000"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_vlan_update"))
def test_vlan_table_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot):
    with patch.object(DbEventChecker, "_subscribe_table"), \
         patch.object(DbEventChecker, "subscribe_table", return_value=MockSubscribeTable(tested_data["table"]),
                      new_callable=PropertyMock):
        sel = swsscommon.Select()
        db_connector = DhcpDbConnector()
        db_event_checker = VlanTableEventChecker(sel, db_connector)
        expected_res = tested_data["exp_res"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "enabled_dhcp_interfaces" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res


@pytest.mark.parametrize("tested_db_snapshot", [{"enabled_dhcp_interfaces": "Vlan1000"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_vlan_intf_update"))
def test_vlan_intf_table_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot):
    with patch.object(DbEventChecker, "_subscribe_table"), \
         patch.object(DbEventChecker, "subscribe_table", return_value=MockSubscribeTable(tested_data["table"]),
                      new_callable=PropertyMock):
        sel = swsscommon.Select()
        db_connector = DhcpDbConnector()
        db_event_checker = VlanIntfTableEventChecker(sel, db_connector)
        expected_res = tested_data["exp_res"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "enabled_dhcp_interfaces" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res


@pytest.mark.parametrize("tested_db_snapshot", [{"enabled_dhcp_interfaces": "Vlan1000"}, {}])
@pytest.mark.parametrize("tested_data", get_subscribe_table_tested_data("test_vlan_member_update"))
def test_vlan_member_table_checker(mock_swsscommon_dbconnector_init, tested_data, tested_db_snapshot):
    with patch.object(DbEventChecker, "_subscribe_table"), \
         patch.object(DbEventChecker, "subscribe_table", return_value=MockSubscribeTable(tested_data["table"]),
                      new_callable=PropertyMock):
        sel = swsscommon.Select()
        db_connector = DhcpDbConnector()
        db_event_checker = VlanMemberTableEventChecker(sel, db_connector)
        expected_res = tested_data["exp_res"]
        check_res = db_event_checker.check_update_event(tested_db_snapshot)
        if "enabled_dhcp_interfaces" not in tested_db_snapshot:
            assert check_res
        else:
            assert expected_res == check_res
