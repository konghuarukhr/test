#!/usr/bin/env bash

IFACE=eth0

IP=`ifconfig ${IFACE} | grep inet | cut -d ' ' -f 12 | cut -d ':' -f 2`
iptables -t nat -F
iptables -t nat -A POSTROUTING -o ${IFACE} ! -s ${IP} -j SNAT --to-source ${IP}
