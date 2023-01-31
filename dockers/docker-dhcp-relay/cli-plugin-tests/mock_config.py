TEST_DATA = [
    [
        "ipv6",
        {
            "config_db": {
                "DHCP_RELAY": {
                    "Vlan1000": {
                        "dhcpv6_servers": [
                            "fc02:2000::1",
                            "fc02:2000::2"
                        ],
                        "dhcpv6_option|rfc6939_support": "true"
                    }
                }
            }
        },
    ],
    [
        "ipv4",
        {
            "config_db": {
                "VLAN": {
                    "Vlan1000": {
                        "dhcp_servers": [
                            "192.0.0.1",
                            "192.0.0.2"
                        ]
                    }
                }
            }
        }
    ]
]
