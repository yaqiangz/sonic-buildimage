# docker image for sonic config engine

DOCKER_CONFIG_ENGINE_BOOKWORM = docker-config-engine-bookworm.gz
$(DOCKER_CONFIG_ENGINE_BOOKWORM)_PATH = $(DOCKERS_PATH)/docker-config-engine-bookworm

$(DOCKER_CONFIG_ENGINE_BOOKWORM)_DEPENDS += $(LIBSWSSCOMMON) \
                                          $(LIBYANG) \
                                          $(LIBYANG_CPP) \
                                          $(LIBYANG_PY3) \
                                          $(PYTHON3_SWSSCOMMON) \
                                          $(SONIC_DB_CLI) \
                                          $(SONIC_EVENTD)
$(DOCKER_CONFIG_ENGINE_BOOKWORM)_PYTHON_WHEELS += $(SONIC_PY_COMMON_PY3) \
                                                  $(SONIC_YANG_MGMT_PY3) \
                                                  $(SONIC_YANG_MODELS_PY3) \
                                                  $(SONIC_CONTAINERCFGD)
$(DOCKER_CONFIG_ENGINE_BOOKWORM)_PYTHON_WHEELS += $(SONIC_CONFIG_ENGINE_PY3)
$(DOCKER_CONFIG_ENGINE_BOOKWORM)_LOAD_DOCKERS += $(DOCKER_BASE_BOOKWORM)
$(DOCKER_CONFIG_ENGINE_BOOKWORM)_FILES += $(SWSS_VARS_TEMPLATE)
$(DOCKER_CONFIG_ENGINE_BOOKWORM)_FILES += $(RSYSLOG_PLUGIN_CONF_J2)
$(DOCKER_CONFIG_ENGINE_BOOKWORM)_FILES += $($(SONIC_CTRMGRD)_CONTAINER_SCRIPT)
$(DOCKER_CONFIG_ENGINE_BOOKWORM)_FILES += $($(SONIC_CTRMGRD)_HEALTH_PROBE)
$(DOCKER_CONFIG_ENGINE_BOOKWORM)_FILES += $($(SONIC_CTRMGRD)_STARTUP_SCRIPT)

$(DOCKER_CONFIG_ENGINE_BOOKWORM)_DBG_DEPENDS = $($(DOCKER_BASE_BOOKWORM)_DBG_DEPENDS) \
                                             $(LIBSWSSCOMMON_DBG) \
                                             $(LIBHIREDIS_DBG)
$(DOCKER_CONFIG_ENGINE_BOOKWORM)_DBG_IMAGE_PACKAGES = $($(DOCKER_BASE_BOOKWORM)_DBG_IMAGE_PACKAGES)

SONIC_DOCKER_IMAGES += $(DOCKER_CONFIG_ENGINE_BOOKWORM)
