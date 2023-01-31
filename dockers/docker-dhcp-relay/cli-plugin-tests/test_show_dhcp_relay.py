import pytest
import sys
import os
sys.path.append('../cli/show/plugins/')
import show_dhcp_relay as show
from swsscommon import swsscommon
from mock_config import TEST_DATA
from parameterized import parameterized
from pyfakefs.fake_filesystem_unittest import patchfs

try:
    sys.path.insert(0, '../../../src/sonic-host-services/tests/common')
    from mock_configdb import MockConfigDb
    swsscommon.ConfigDBConnector = MockConfigDb
except KeyError:
    pass

expected_ipv6_table = """\
--------  ------------
Vlan1000  fc02:2000::1
          fc02:2000::2
--------  ------------
"""

expected_ipv4_table = """\
--------  ---------
Vlan1000  192.0.0.1
          192.0.0.2
--------  ---------
"""

DBCONFIG_PATH = '/var/run/redis/sonic-db/database_config.json'

IP_VER_TEST_PARAM_MAP = {
    "ipv4": {
        "entry": "dhcp_servers",
        "table": "VLAN"
    },
    "ipv6": {
        "entry": "dhcpv6_servers",
        "table": "DHCP_RELAY"
    }
}


@parameterized.expand(TEST_DATA)
@patchfs
def test_show_dhcp_relay(test_name, test_data, fs):
    if not os.path.exists(DBCONFIG_PATH):
        fs.create_file(DBCONFIG_PATH)
    MockConfigDb.set_config_db(test_data["config_db"])
    config_db = MockConfigDb()
    table = config_db.get_table(IP_VER_TEST_PARAM_MAP[test_name]["table"])
    result = show.get_data(table, "Vlan1000", IP_VER_TEST_PARAM_MAP[test_name]["entry"])
    assert result == (expected_ipv4_table if test_name == "ipv4" else expected_ipv6_table)
