# sonic-dhcpservd package

SONIC_DHCPSERVD_PY3 = sonic_dhcpservd-1.0-py3-none-any.whl
$(SONIC_DHCPSERVD_PY3)_SRC_PATH = $(SRC_PATH)/sonic-dhcpservd
$(SONIC_DHCPSERVD_PY3)_PYTHON_VERSION = 3
ifeq ($(INCLUDE_DHCP_SERVER), y)
SONIC_PYTHON_WHEELS += $(SONIC_DHCPSERVD_PY3)
endif
