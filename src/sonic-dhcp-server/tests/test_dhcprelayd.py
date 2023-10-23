import psutil
import pytest
import subprocess
import sys
import time
from common_utils import mock_get_config_db_table, MockSelect, MockSubscribeTable, MockProc
from dhcp_server.dhcp_server_utils import DhcpDbConnector
from dhcp_server.dhcprelayd import DhcpRelayd, KILLED_OLD, NOT_KILLED, NOT_FOUND_PROC
from swsscommon import swsscommon
from unittest.mock import patch, call, ANY, PropertyMock, MagicMock


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
         patch.object(DhcpDbConnector, "get_config_db_table", side_effect=mock_get_config_db_table), \
         patch.object(DhcpRelayd, "_start_dhcrelay_process", return_value=None), \
         patch.object(DhcpRelayd, "_start_dhcpmon_process", return_value=None):
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        dhcprelayd.refresh_dhcrelay()


def test_subscribe_config_db(mock_swsscommon_dbconnector_init):
    with patch.object(swsscommon, "SubscriberStateTable", side_effect=mock_subscriber_state_table) as mock_subscribe, \
         patch.object(swsscommon.Select, "addSelectable", return_value=None) as mock_add_select:
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        dhcprelayd._subscribe_config_db()
        mock_subscribe.assert_has_calls([
            call(ANY, "DHCP_SERVER_IPV4"),
            call(ANY, "VLAN")
        ])
        mock_add_select.assert_has_calls([
            call("DHCP_SERVER_IPV4"),
            call("VLAN")
        ])


@pytest.mark.parametrize("select_result", [swsscommon.Select.TIMEOUT, swsscommon.Select.OBJECT])
def test_config_db_update_event(mock_swsscommon_dbconnector_init, select_result):
    with patch.object(DhcpRelayd, "_dhcp_server_update_event", side_effect=None) as mock_dhcp_update, \
         patch.object(DhcpRelayd, "_vlan_update_event", return_value=None) as mock_vlan_update, \
         patch.object(DhcpRelayd, "sel", return_value=MockSelect(), new_callable=PropertyMock), \
         patch.object(MockSelect, "select", return_value=(select_result, None)):
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        dhcprelayd._config_db_update_event()
        if select_result == swsscommon.Select.TIMEOUT:
            mock_dhcp_update.assert_not_called()
            mock_vlan_update.assert_not_called()
        else:
            mock_dhcp_update.assert_called_once_with()
            mock_vlan_update.assert_called_once_with()


def test_dhcp_server_update_event(mock_swsscommon_dbconnector_init):
    with patch.object(DhcpRelayd, "subscribe_dhcp_server_table", return_value=MockSubscribeTable("DHCP_SERVER_IPV4"),
                      new_callable=PropertyMock), \
         patch.object(DhcpRelayd, "dhcp_interfaces_state", return_value={"Vlan1000": "enabled"},
                      new_callable=PropertyMock), \
         patch.object(DhcpRelayd, "refresh_dhcrelay", return_value=None) as mock_refresh:
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        while len(dhcprelayd.subscribe_dhcp_server_table.stack) != 0:
            dhcprelayd._dhcp_server_update_event()
        mock_refresh.assert_has_calls([
            call(), # del vlan1000
            call() # set vlan2000 state
        ])


def test_vlan_update_event(mock_swsscommon_dbconnector_init):
    mock_dhcp_interface_state = {"Vlan1000": "enabled", "Vlan1001": "disabled", "Vlan1002": "disabled"}
    with patch.object(DhcpRelayd, "subscribe_vlan_table", return_value=MockSubscribeTable("VLAN"),
                      new_callable=PropertyMock), \
         patch.object(DhcpRelayd, "dhcp_interfaces_state", return_value=mock_dhcp_interface_state,
                      new_callable=PropertyMock), \
         patch.object(DhcpRelayd, "refresh_dhcrelay", return_value=None) as mock_refresh:
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        while len(dhcprelayd.subscribe_vlan_table.stack) != 0:
            dhcprelayd._vlan_update_event()
        mock_refresh.assert_called_once_with() # set vlan1000


@pytest.mark.parametrize("new_dhcp_interfaces", [[], ["Vlan1000"], ["Vlan1000", "Vlan2000"]])
@pytest.mark.parametrize("kill_res", [KILLED_OLD, NOT_KILLED, NOT_FOUND_PROC])
def test_start_dhcrelay_process(mock_swsscommon_dbconnector_init, new_dhcp_interfaces, kill_res):
    with patch.object(DhcpRelayd, "_kill_exist_relay_releated_process", return_value=kill_res), \
         patch.object(subprocess, "Popen", return_value=None) as mock_popen:
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        dhcprelayd._start_dhcrelay_process(new_dhcp_interfaces, "240.127.1.2")
        if len(new_dhcp_interfaces) == 0 or kill_res == NOT_KILLED:
            mock_popen.assert_not_called()
        else:
            call_param = ["/usr/sbin/dhcrelay", "-d", "-m", "discard", "-a", "%h:%p", "%P", "--name-alias-map-file", "/tmp/port-name-alias-map.txt"]
            for interface in new_dhcp_interfaces:
                call_param += ["-id", interface]
            call_param += ["-iu", "docker0", "240.127.1.2"]
            mock_popen.assert_called_once_with(call_param)
    

@pytest.mark.parametrize("new_dhcp_interfaces_list", [[], ["Vlan1000"], ["Vlan1000", "Vlan2000"]])
@pytest.mark.parametrize("kill_res", [KILLED_OLD, NOT_KILLED, NOT_FOUND_PROC])
def test_start_dhcpmon_process(mock_swsscommon_dbconnector_init, new_dhcp_interfaces_list, kill_res):
    new_dhcp_interfaces = set(new_dhcp_interfaces_list)
    with patch.object(DhcpRelayd, "_kill_exist_relay_releated_process", return_value=kill_res), \
         patch.object(subprocess, "Popen", return_value=None) as mock_popen:
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        dhcprelayd._start_dhcpmon_process(new_dhcp_interfaces)
        if len(new_dhcp_interfaces) == 0 or kill_res == NOT_KILLED:
            mock_popen.assert_not_called()
        else:
            calls = []
            for interface in new_dhcp_interfaces:
                call_param = ["/usr/sbin/dhcpmon", "-id", interface, "-iu", "docker0", "-im", "eth0"]
                calls.append(call(call_param))
            mock_popen.assert_has_calls(calls)


@pytest.mark.parametrize("new_dhcp_interfaces_list", [[], ["Vlan1000"], ["Vlan1000", "Vlan2000"]])
@pytest.mark.parametrize("process_name", ["dhcrelay", "dhcpmon"])
@pytest.mark.parametrize("running_procs", [[], ["dhcrelay"], ["dhcpmon"], ["dhcrelay", "dhcpmon"]])
def test_kill_exist_relay_releated_process(mock_swsscommon_dbconnector_init, new_dhcp_interfaces_list, process_name, running_procs):
    new_dhcp_interfaces = set(new_dhcp_interfaces_list)
    process_iter_ret = []
    for running_proc in running_procs:
        process_iter_ret.append(MockProc(running_proc))
    with patch.object(psutil, "process_iter", return_value=process_iter_ret):
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        res = dhcprelayd._kill_exist_relay_releated_process(new_dhcp_interfaces, process_name)
        if process_name == "dhcrelay" and new_dhcp_interfaces_list == ["Vlan1000"] and "dhcrelay" in running_procs:
            assert res == NOT_KILLED
        elif process_name == "dhcpmon" and new_dhcp_interfaces_list == ["Vlan1000"] and "dhcpmon" in running_procs:
            assert res == NOT_KILLED
        elif process_name not in running_procs:
            assert res == NOT_FOUND_PROC
        elif new_dhcp_interfaces_list != ["Vlan1000"]:
            assert res == KILLED_OLD


def test_get_dhcp_server_ip(mock_swsscommon_dbconnector_init, mock_swsscommon_table_init):
    tested_ip = "240.127.1.2"
    with patch.object(swsscommon.Table, "hget", return_value=(1, tested_ip)):
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        ret = dhcprelayd._get_dhcp_server_ip()
        assert ret == tested_ip


def mock_subscriber_state_table(db, table_name):
    return table_name
