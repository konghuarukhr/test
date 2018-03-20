#ifndef _GENL_H_
#define _GENL_H_
#include <stdint.h>
#include <stdbool.h>

struct genlsk;

#define GENL_LENGTH(len) NLMSG_LENGTH((len) + GENL_HDRLEN)
#define GENL_SPACE(len) NLMSG_SPACE((len) + GENL_HDRLEN)
#define GENL_DATA(nlh) (void *)((char *)NLMSG_DATA(nlh) + GENL_HDRLEN)
#define BUF_SIZE 4096

struct genlsk {
	char buf[BUF_SIZE];
	char *cur;
	int fd;
	uint16_t faid;
	uint32_t seq;
	uint32_t pid;
};



struct genlsk *open_genl_socket(const char *name);
int close_genl_socket(struct genlsk *genlsk);
int send_nl_cmd(struct genlsk *genlsk);
int recv_nl_resp(struct genlsk *genlsk);
void put_nl_hdr(struct genlsk *genlsk);
void put_nl_hdr_dump(struct genlsk *genlsk);
void put_genl_hdr(struct genlsk *genlsk, uint8_t cmd);
bool add_nl_attr(struct genlsk *genlsk, uint16_t type, const void *data,
		int len);

#endif
