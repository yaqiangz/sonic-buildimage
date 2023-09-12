#!/usr/bin/env bash


# Generate supervisord config file
mkdir -p /etc/supervisor/conf.d/
# Generate kea folder
mkdir -p /etc/kea/

# Generate the following files from templates:
# port-to-alias name map
CFGGEN_PARAMS=" \
    -d \
    -t /usr/share/sonic/templates/port-name-alias-map.txt.j2,/tmp/port-name-alias-map.txt \
"
sonic-cfggen $CFGGEN_PARAMS

# Make the script that waits for all interfaces to come up executable
chmod +x /etc/kea/lease_update.sh /usr/bin/start.sh
# The docker container should start this script as PID 1, so now that supervisord is
# properly configured, we exec /usr/local/bin/supervisord so that it runs as PID 1 for the
# duration of the container's lifetime
exec /usr/local/bin/supervisord
