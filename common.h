#include <linux/module.h>
#define LICENSE "GPL"
#define VERSION "1.0"
#define AUTHOR "Dustin Zheng <konghuarukhr@gmail.com>"

#ifdef CLIENT
#define ALIAS "iproxy_client"
#define DESCRIPTION "An IP proxy client"
#define LOG_INFO(msg) printk(KERN_INFO CLIENT_ALIAS ":" msg "\n")
#define LOG_ERROR(msg) printk(KERN_ERROR msg "\n")
#else /* SERVER */
#define ALIAS "iproxy_server"
#define DESCRIPTION "An IP proxy server"
#endif

#define LINE(msg) (msg "\n")
#define LOG_INFO(msg, ...) printk(KERN_INFO ALIAS ": " LINE(msg), __VA_ARGS__)
#define LOG_ERROR(msg, ...) printk(KERN_ERROR ALIAS ": " LINE(msg), __VA_ARGS__)

