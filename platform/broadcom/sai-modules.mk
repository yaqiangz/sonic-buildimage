# Broadcom SAI modules

BRCM_OPENNSL_KERNEL_VERSION = 12.1.0.2

BRCM_OPENNSL_KERNEL = opennsl-modules_$(BRCM_OPENNSL_KERNEL_VERSION)_amd64.deb
$(BRCM_OPENNSL_KERNEL)_SRC_PATH = $(PLATFORM_PATH)/saibcm-modules
$(BRCM_OPENNSL_KERNEL)_DEPENDS += $(LINUX_HEADERS) $(LINUX_HEADERS_COMMON)
$(BRCM_OPENNSL_KERNEL)_BUILD_ENV += PKG_NAME=$(BRCM_OPENNSL_KERNEL)
$(BRCM_OPENNSL_KERNEL)_MACHINE = broadcom
SONIC_DPKG_DEBS += $(BRCM_OPENNSL_KERNEL)

# SAI bcm modules for DNX family ASIC
BRCM_DNX_OPENNSL_KERNEL_VERSION = 11.2.13.1-1

BRCM_DNX_OPENNSL_KERNEL = opennsl-modules-dnx_$(BRCM_DNX_OPENNSL_KERNEL_VERSION)_amd64.deb
$(BRCM_DNX_OPENNSL_KERNEL)_SRC_PATH = $(PLATFORM_PATH)/saibcm-modules-dnx
$(BRCM_DNX_OPENNSL_KERNEL)_DEPENDS += $(LINUX_HEADERS) $(LINUX_HEADERS_COMMON)
$(BRCM_DNX_OPENNSL_KERNEL)_BUILD_ENV += PKG_NAME=$(BRCM_DNX_OPENNSL_KERNEL)
$(BRCM_DNX_OPENNSL_KERNEL)_MACHINE = broadcom-dnx
$(BRCM_DNX_OPENNSL_KERNEL)_AFTER = $(BRCM_OPENNSL_KERNEL)
SONIC_DPKG_DEBS += $(BRCM_DNX_OPENNSL_KERNEL)
