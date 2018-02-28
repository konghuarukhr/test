#!/usr/bin/env bash

# output interface
IFACE=eth0

IP=`ifconfig ${IFACE} | grep inet | cut -d ' ' -f 12 | cut -d ':' -f 2`
iptables -t nat -D POSTROUTING -o ${IFACE} ! -s ${IP} -j SNAT --to-source ${IP} &> /dev/null
iptables -t nat -A POSTROUTING -o ${IFACE} ! -s ${IP} -j SNAT --to-source ${IP}
