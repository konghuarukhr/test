#ifndef _COMMON_H_
#define _COMMON_H_

#include <linux/module.h>
#define LICENSE "GPL"
#define VERSION "1.0"
#define AUTHOR "Dustin Zheng <konghuarukhr@gmail.com>"

#ifdef CLIENT
#define ALIAS "iproxy_client"
#define DESCRIPTION "An IP proxy client"
#else /* SERVER */
#define ALIAS "iproxy_server"
#define DESCRIPTION "An IP proxy server"
#endif

//#define LINE(msg) (msg "\n")
#define LINE(msg) msg "\n"
#define LOG_INFO(msg, ...) pr_info(ALIAS ": " LINE(msg), ##__VA_ARGS__)
//#define LOG_INFO pr_info
#define LOG_ERROR(msg, ...) pr_err(ALIAS ": " LINE(msg), ##__VA_ARGS__)
//#define LOG_ERROR(msg, ...) pr_err(msg, ##__VA_ARGS__)
//#define LOG_ERROR pr_err

#include <net/net_namespace.h>
#include <net/sock.h>
//#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/moduleparam.h>
#include <linux/inet.h>
#include <linux/printk.h>
#include <linux/hashtable.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <net/genetlink.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <generated/uapi/linux/version.h>

#include "ipr.h"
#include "masq.h"
#include "route.h"
#include "xlate.h"

#endif
