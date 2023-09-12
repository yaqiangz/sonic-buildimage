#!/bin/bash

pid=`ps aux | grep 'python3 dhcpservd.py' | grep -nv 'grep' | awk '{print $2}'`
kill -s 10 ${pid}
