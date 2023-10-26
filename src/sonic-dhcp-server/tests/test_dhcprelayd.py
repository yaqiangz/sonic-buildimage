import psutil
import pytest
import subprocess
import sys
import time
from common_utils import mock_get_config_db_table, MockSelect, MockSubscribeTable, MockProc
from dhcp_server.dhcp_server_utils import DhcpDbConnector
from dhcp_server.dhcprelayd import DhcpRelayd, KILLED_OLD, NOT_KILLED, NOT_FOUND_PROC
from swsscommon import swsscommon
from unittest.mock import patch, call, ANY, PropertyMock

tested_subscribe_dhcp_server_table = [
    {
        "table": [
            ("Vlan1000", "SET", (("customized_options", "option1"), ("state", "enabled"),))
        ],
        "exp_res": True
    },
    {
        "table": [
            ("Vlan2000", "SET", (("state", "enabled"),))
        ],
        "exp_res": True
    },
    {
        "table": [
            ("Vlan1000", "DEL", ())
        ],
        "exp_res": True
    },
    {
        "table": [
            ("Vlan2000", "DEL", ())
        ],
        "exp_res": False
    },
    {
        "table": [
            ("Vlan2000", "DEL", ()),
            ("Vlan1000", "DEL", ())
        ],
        "exp_res": True
    }
]
tested_subscribe_vlan_table = [
    {
        "table": [
            ("Vlan1000", "SET", (("vlanid", "1000"),))
        ],
        "exp_res": True
    },
    {
        "table": [
            ("Vlan1001", "SET", (("vlanid", "1001"),))
        ],
        "exp_res": False
    },
    {
        "table": [
            ("Vlan1000", "SET", (("vlanid", "1000"),)),
            ("Vlan1002", "SET", (("vlanid", "1002"),))
        ],
        "exp_res": True
    },
    {
        "table": [
            ("Vlan1001", "DEL", ())
        ],
        "exp_res": False
    },
    {
        "table": [
            ("Vlan1000", "DEL", ())
        ],
        "exp_res": True
    },
    {
        "table": [
            ("Vlan1000", "SET", (("vlanid", "1000"),)),
            ("Vlan1001", "DEL", ())
        ],
        "exp_res": True
    }
]


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
@pytest.mark.parametrize("dhcp_server_update_result", [swsscommon.Select.TIMEOUT, swsscommon.Select.OBJECT])
@pytest.mark.parametrize("vlan_update_result", [swsscommon.Select.TIMEOUT, swsscommon.Select.OBJECT])
def test_config_db_update_event(mock_swsscommon_dbconnector_init, select_result, dhcp_server_update_result,
                                vlan_update_result):
    with patch.object(DhcpRelayd, "_check_dhcp_server_update", return_value=dhcp_server_update_result) \
        as mock_dhcp_update, \
         patch.object(DhcpRelayd, "_check_vlan_update", return_value=vlan_update_result) as mock_vlan_update, \
         patch.object(DhcpRelayd, "sel", return_value=MockSelect(), new_callable=PropertyMock), \
         patch.object(MockSelect, "select", return_value=(select_result, None)), \
         patch.object(DhcpRelayd, "refresh_dhcrelay") as mock_refresh:
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        dhcprelayd._config_db_update_event()
        if select_result == swsscommon.Select.TIMEOUT:
            mock_dhcp_update.assert_not_called()
            mock_vlan_update.assert_not_called()
            mock_refresh.assert_not_called()
        else:
            mock_dhcp_update.assert_called_once_with()
            mock_vlan_update.assert_called_once_with()
            if dhcp_server_update_result or vlan_update_result:
                mock_refresh.assert_called_once_with()


@pytest.mark.parametrize("dhcp_server_table_update", tested_subscribe_dhcp_server_table)
def test_dhcp_server_update_event(mock_swsscommon_dbconnector_init, dhcp_server_table_update):
    tested_table = dhcp_server_table_update["table"]
    with patch.object(DhcpRelayd, "subscribe_dhcp_server_table",
                      return_value=MockSubscribeTable(tested_table),
                      new_callable=PropertyMock), \
         patch.object(DhcpRelayd, "dhcp_interfaces_state", return_value={"Vlan1000": "enabled", "Vlan2000": "disabled"},
                      new_callable=PropertyMock):
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        print(dhcp_server_table_update)
        check_res = dhcprelayd._check_dhcp_server_update()
        assert check_res == dhcp_server_table_update["exp_res"]


@pytest.mark.parametrize("vlan_table_update", tested_subscribe_vlan_table)
def test_check_vlan_update(mock_swsscommon_dbconnector_init, vlan_table_update):
    tested_table = vlan_table_update["table"]
    mock_dhcp_interface_state = {"Vlan1000": "enabled", "Vlan1001": "disabled", "Vlan1002": "disabled"}
    with patch.object(DhcpRelayd, "subscribe_vlan_table", return_value=MockSubscribeTable(tested_table),
                      new_callable=PropertyMock), \
         patch.object(DhcpRelayd, "dhcp_interfaces_state", return_value=mock_dhcp_interface_state,
                      new_callable=PropertyMock):
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        check_res = dhcprelayd._check_vlan_update()
        assert check_res == vlan_table_update["exp_res"]


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
            call_param = ["/usr/sbin/dhcrelay", "-d", "-m", "discard", "-a", "%h:%p", "%P", "--name-alias-map-file",
                          "/tmp/port-name-alias-map.txt"]
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
def test_kill_exist_relay_releated_process(mock_swsscommon_dbconnector_init, new_dhcp_interfaces_list, process_name,
                                           running_procs):
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


@pytest.mark.parametrize("get_res", [(1, "240.127.1.2"), (0, None)])
def test_get_dhcp_server_ip(mock_swsscommon_dbconnector_init, mock_swsscommon_table_init, get_res):
    with patch.object(swsscommon.Table, "hget", return_value=get_res), \
         patch.object(time, "sleep") as mock_sleep, \
         patch.object(sys, "exit") as mock_exit:
        dhcp_db_connector = DhcpDbConnector()
        dhcprelayd = DhcpRelayd(dhcp_db_connector)
        ret = dhcprelayd._get_dhcp_server_ip()
        if get_res[0] == 1:
            assert ret == get_res[1]
        else:
            mock_exit.assert_called_once_with(1)
            mock_sleep.assert_has_calls([call(10) for _ in range(10)])


def mock_subscriber_state_table(db, table_name):
    return table_name
