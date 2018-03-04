#ifndef _GENL_H_
#define _GENL_H_

struct genlsk;

struct genlsk *open_genl_socket(const char *name);
int close_genl_socket(struct genlsk *genlsk);
int send_nl_cmd(struct genlsk *genlsk);
int recv_nl_resp(struct genlsk *genlsk);
void put_nl_hdr(struct genlsk *genlsk);
void put_genl_hdr(struct genlsk *genlsk, uint8_t cmd);
void add_nl_attr(struct genlsk *genlsk, uint16_t type, const char *data,
		int len);

#endif
