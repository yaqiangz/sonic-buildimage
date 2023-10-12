from dhcpservd.dhcp_server_utils import DhcpDbConnector
from dhcpservd.dhcp_cfggen import DhcpServCfgGenerator
from dhcpservd.dhcpservd import DhcpServd
from unittest.mock import patch, call, MagicMock


def test_dump_dhcp4_config(mock_swsscommon_dbconnector_init):
    with patch("dhcpservd.dhcp_cfggen.DhcpServCfgGenerator.generate", return_value="dummy_config") as mock_generate, \
         patch("dhcpservd.dhcpservd.DhcpServd._notify_kea_dhcp4_proc", MagicMock()) as mock_notify_kea_dhcp4_proc, \
         patch("dhcpservd.dhcpservd.open", MagicMock()) as mock_write, \
         patch("unittest.mock.call.__enter__", MagicMock()):
        dhcp_db_connector = DhcpDbConnector()
        dhcp_cfg_generator = DhcpServCfgGenerator(dhcp_db_connector,
                                                  port_map_path="tests/test_data/port-name-alias-map.txt",
                                                  kea_conf_template_path="tests/test_data/kea-dhcp4.conf.j2")
        dhcpservd = DhcpServd(dhcp_cfg_generator, dhcp_db_connector, kea_dhcp4_config_path="/tmp/kea-dhcp4.conf")
        dhcpservd.dump_dhcp4_config()
        # Verfiy whether generate() func of dhcp_cfggen is called
        mock_generate.assert_called_once_with()
        # Verify whether new configuration was written to file
        mock_write.assert_has_calls([
            call("/tmp/kea-dhcp4.conf", "w"),
            call().__enter__(),
            call().__enter__().write("dummy_config"),
            call().__exit__(None, None, None)
        ])
        # Verify whether notify func of dhcpservd is called, which is expected to call after new config generated
        mock_notify_kea_dhcp4_proc.assert_called_once_with()
