import dhcpservd.dhcp_lease as dhcp_lease
import dhcpservd.dhcp_server_utils as dhcp_server_utils
from swsscommon import swsscommon
from unittest.mock import patch, call

expected_lease = {
    "Vlan1000|10:70:fd:b6:13:00": {
        "lease_start": "1693997305",
        "lease_end": "1693997305",
        "ip": "192.168.0.2"
    },
    "Vlan1000|10:70:fd:b6:13:17": {
        "lease_start": "1693997315",
        "lease_end": "1694000915",
        "ip": "192.168.0.131"
    }
}


def test_read_kea_lease(mock_swsscommon_dbconnector_init):
    db_connector = dhcp_server_utils.DhcpDbConnector()
    kea_lease_handler = dhcp_lease.KeaDhcp4LeaseHandler(db_connector, lease_file="tests/test_data/kea-lease.csv",
                                                        ip_ports_file="tests/test_data/dhcp_server_ip_ports.json")
    # Verify whether lease information read is as expected
    lease = kea_lease_handler._read()
    assert lease == expected_lease


def test_update_kea_lease(mock_swsscommon_dbconnector_init, mock_swsscommon_table_init):
    with patch.object(swsscommon.Table, "getKeys"), \
         patch.object(swsscommon.DBConnector, "hset") as mock_hset:
        db_connector = dhcp_server_utils.DhcpDbConnector()
        kea_lease_handler = dhcp_lease.KeaDhcp4LeaseHandler(db_connector, lease_file="tests/test_data/kea-lease.csv",
                                                            ip_ports_file="tests/test_data/dhcp_server_ip_ports.json")
        kea_lease_handler.update_lease()
        # Verify that lease has been updated, to be noted that lease for "192.168.0.2" didn't been updated because
        # lease_start equals to lease_end
        mock_hset.assert_has_calls([
            call('DHCP_SERVER_IPV4_LEASE|Vlan1000|10:70:fd:b6:13:17', 'lease_start', '1693997315'),
            call('DHCP_SERVER_IPV4_LEASE|Vlan1000|10:70:fd:b6:13:17', 'lease_end', '1694000915'),
            call('DHCP_SERVER_IPV4_LEASE|Vlan1000|10:70:fd:b6:13:17', 'ip', '192.168.0.131')
        ])
