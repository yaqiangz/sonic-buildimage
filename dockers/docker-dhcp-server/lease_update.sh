#!/bin/bash

pid=`ps aux | grep 'dhcpservd.py' | grep -nv 'grep' | awk '{print $2}'`
kill -s 10 ${pid}
