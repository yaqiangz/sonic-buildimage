# libevent
ifeq ($(BLDENV),bookworm)
	LIBEVENT_VERSION = 2.1.12
else
	LIBEVENT_VERSION = 2.1.8
endif

export LIBEVENT_VERSION

LIBEVENT = libevent_$(LIBEVENT_VERSION)_amd64.deb
$(LIBEVENT)_DPKGFLAGS += --force-all
$(LIBEVENT)_SRC_PATH = $(SRC_PATH)/libevent
SONIC_MAKE_DEBS += $(LIBEVENT)
