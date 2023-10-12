import json
import pytest
from common_utils import MockConfigDb
from dhcpservd.dhcp_server_utils import DhcpDbConnector
from dhcpservd.dhcp_cfggen import DhcpServCfgGenerator
from unittest.mock import patch, MagicMock, ANY

expected_dhcp_config = {
    "Dhcp4": {
        "hooks-libraries": [
            {
                "library": "/usr/local/lib/kea/hooks/libdhcp_run_script.so",
                "parameters": {
                    "name": "/etc/kea/lease_update.sh",
                    "sync": False
                }
            }
        ],
        "interfaces-config": {
            "interfaces": [
                "eth0"
            ]
        },
        "control-socket": {
            "socket-type": "unix",
            "socket-name": "/run/kea/kea4-ctrl-socket"
        },
        "lease-database": {
            "type": "memfile",
            "persist": True,
            "name": "/tmp/kea-lease.csv",
            "lfc-interval": 3600
        },
        "subnet4": [
            {
                "subnet": "192.168.0.0/21",
                "pools": [
                    {
                        "pool": "192.168.0.7 - 192.168.0.7",
                        "client-class": "sonic-host:etp7"
                    },
                    {
                        "pool": "192.168.0.2 - 192.168.0.6",
                        "client-class": "sonic-host:etp8"
                    },
                    {
                        "pool": "192.168.0.10 - 192.168.0.10",
                        "client-class": "sonic-host:etp8"
                    }
                ],
                "option-data": [
                    {
                        "name": "routers",
                        "data": "192.168.0.1"
                    },
                    {
                        "name": "dhcp-server-identifier",
                        "data": "192.168.0.1"
                    }
                ],
                "valid-lifetime": 900,
                "reservations": []
            }
        ],
        "loggers": [
            {
                "name": "kea-dhcp4",
                "output_options": [
                    {
                        "output": "/var/log/kea-dhcp.log",
                        "pattern": "%-5p %m\n"
                    }
                ],
                "severity": "INFO",
                "debuglevel": 0
            }
        ],
        "client-classes": [
            {
                "name": "sonic-host:etp7",
                "test": "substring(relay4[1].hex, -15, 15) == 'sonic-host:etp7'"
            },
            {
                "name": "sonic-host:etp8",
                "test": "substring(relay4[1].hex, -15, 15) == 'sonic-host:etp8'"
            }
        ]
    }
}
expected_dhcp_config_without_port_config = {
    "Dhcp4": {
        "hooks-libraries": [
            {
                "library": "/usr/local/lib/kea/hooks/libdhcp_run_script.so",
                "parameters": {
                    "name": "/etc/kea/lease_update.sh",
                    "sync": False
                }
            }
        ],
        "interfaces-config": {
            "interfaces": [
                "eth0"
            ]
        },
        "control-socket": {
            "socket-type": "unix",
            "socket-name": "/run/kea/kea4-ctrl-socket"
        },
        "lease-database": {
            "type": "memfile",
            "persist": True,
            "name": "/tmp/kea-lease.csv",
            "lfc-interval": 3600
        },
        "subnet4": [
        ],
        "loggers": [
            {
                "name": "kea-dhcp4",
                "output_options": [
                    {
                        "output": "/var/log/kea-dhcp.log",
                        "pattern": "%-5p %m\n"
                    }
                ],
                "severity": "INFO",
                "debuglevel": 0
            }
        ]
    }
}


@pytest.mark.parametrize("test_config_db", ["mock_config_db.json", "mock_config_db_without_port_config.json"])
def test_generate_dhcp_config(mock_swsscommon_dbconnector_init, test_config_db):
    mock_config_db = MockConfigDb(config_db_path="tests/test_data/{}".format(test_config_db))
    with patch("dhcpservd.dhcp_server_utils.DhcpDbConnector.get_config_db_table",
               MagicMock(side_effect=mock_config_db.get_config_db_table)), \
         patch("json.dump") as mock_json_dump:
        dhcp_db_connector = DhcpDbConnector()
        dhcp_cfg_generator = DhcpServCfgGenerator(dhcp_db_connector,
                                                  port_map_path="tests/test_data/port-name-alias-map.txt",
                                                  kea_conf_template_path="tests/test_data/kea-dhcp4.conf.j2")
        config = dhcp_cfg_generator.generate()
        # Verify whether configuration generated as expected.
        if test_config_db == "mock_config_db.json":
            assert json.loads(config) == expected_dhcp_config
            # While generating configuration, we will use json.dump to save net-interface information, verify that.
            mock_json_dump.assert_called_once_with({"192.168.0.0/21": "Vlan1000"}, ANY, indent=4, ensure_ascii=False)
        else:
            assert json.loads(config) == expected_dhcp_config_without_port_config
            mock_json_dump.assert_called_once_with({}, ANY, indent=4, ensure_ascii=False)
