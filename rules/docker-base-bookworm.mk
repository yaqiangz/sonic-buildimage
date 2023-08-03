# Docker base image (based on Debian Bookworm)

DOCKER_BASE_BOOKWORM = docker-base-bookworm.gz
$(DOCKER_BASE_BOOKWORM)_PATH = $(DOCKERS_PATH)/docker-base-bookworm

$(DOCKER_BASE_BOOKWORM)_DEPENDS += $(SOCAT)

GDB = gdb
GDBSERVER = gdbserver
VIM = vim
OPENSSH = openssh-client
SSHPASS = sshpass
STRACE = strace

ifeq ($(INCLUDE_FIPS), y)
$(DOCKER_BASE_BOOKWORM)_DEPENDS += $(FIPS_OPENSSL_LIBSSL) $(FIPS_OPENSSL_LIBSSL_DEV) $(FIPS_OPENSSL) $(SYMCRYPT_OPENSSL) $(FIPS_KRB5)
endif

$(DOCKER_BASE_BOOKWORM)_DBG_IMAGE_PACKAGES += $(GDB) $(GDBSERVER) $(VIM) $(OPENSSH) $(SSHPASS) $(STRACE)

SONIC_DOCKER_IMAGES += $(DOCKER_BASE_BOOKWORM)
