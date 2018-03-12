#!/usr/bin/env bash

rmmod iproxy-client &> /dev/null
insmod iproxy-client.ko server_ip=47.52.88.28 client_port=2357 server_port=2357 dns_ip=8.8.8.8
