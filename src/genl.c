#include "genl.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/genetlink.h>
#include <unistd.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

static inline void update_nl_hdr_len(struct genlsk *genlsk)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->buf;
	nlh->nlmsg_len = genlsk->cur - genlsk->buf;
}

static inline bool is_nl_buf_enough(struct genlsk *genlsk, int len)
{
	if (genlsk->cur + len > genlsk->buf + BUF_SIZE)
		return false;
	return true;
}

void put_nl_hdr(struct genlsk *genlsk)
{
	genlsk->cur = genlsk->buf;
	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->cur;
	nlh->nlmsg_type = genlsk->faid;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = ++genlsk->seq;
	nlh->nlmsg_pid = genlsk->pid;
	genlsk->cur += NLMSG_HDRLEN;
	update_nl_hdr_len(genlsk);
}

void put_nl_hdr_dump(struct genlsk *genlsk)
{
	genlsk->cur = genlsk->buf;
	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->cur;
	nlh->nlmsg_type = genlsk->faid;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = ++genlsk->seq;
	nlh->nlmsg_pid = genlsk->pid;
	genlsk->cur += NLMSG_HDRLEN;
	update_nl_hdr_len(genlsk);
}

void put_genl_hdr(struct genlsk *genlsk, uint8_t cmd)
{
	struct genlmsghdr *genlh = (struct genlmsghdr *)genlsk->cur;
	genlh->cmd = cmd;
	genlh->version = 0x01;
	genlsk->cur += GENL_HDRLEN;
	update_nl_hdr_len(genlsk);
}

bool add_nl_attr(struct genlsk *genlsk, uint16_t type, const void *data,
		int len)
{
	if (!is_nl_buf_enough(genlsk, len))
		return false;

	struct nlattr *nla = (struct nlattr *)genlsk->cur;
	nla->nla_len = NLA_HDRLEN + len;
	nla->nla_type = type;
	memcpy((char *)nla + NLA_HDRLEN, data, len);
	genlsk->cur += NLA_ALIGN(nla->nla_len);
	update_nl_hdr_len(genlsk);
	return true;
}

int send_nl_cmd(struct genlsk *genlsk)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->buf;
	int len = nlh->nlmsg_len;
	int off = 0;
	while (off < len) {
		int ret = send(genlsk->fd, genlsk->buf + off, len - off, 0);
		if (off < 0) {
			fprintf(stderr, "%s\n", strerror(errno));
			return -1;
		}
		off += ret;
	}
	return off;
}

int recv_nl_resp(struct genlsk *genlsk)
{
	int len = recv(genlsk->fd, genlsk->buf, sizeof genlsk->buf, 0);
	if (len < 0) {
		return -1;
	}

	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->buf;
	if (!NLMSG_OK(nlh, len)) {
		return -1;
	}
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		return -1;
	}

	return len;
}


struct genlsk *open_genl_socket(const char *name)
{
	struct genlsk *genlsk = malloc(sizeof *genlsk);
	if (!genlsk) {
		fprintf(stderr, "failed to alloc genlsk: %s\n",
				strerror(errno));
		goto malloc_err;
	}

	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0) {
		fprintf(stderr, "failed to open socket: %s\n", strerror(errno));
		goto socket_err;
	}

	struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	struct sockaddr_nl dst;
	memset(&dst, 0, sizeof dst);
	dst.nl_family = AF_NETLINK;
	if (connect(fd, (struct sockaddr *)&dst, sizeof dst) < 0) {
		fprintf(stderr, "failed to connect: %s\n", strerror(errno));
		goto connect_err;
	}

	genlsk->fd = fd;
	genlsk->faid = GENL_ID_CTRL;
	genlsk->seq = 0;
	genlsk->pid = getpid();

	put_nl_hdr(genlsk);
	put_genl_hdr(genlsk, CTRL_CMD_GETFAMILY);
	add_nl_attr(genlsk, CTRL_ATTR_FAMILY_NAME, name, strlen(name) + 1);

	if (send_nl_cmd(genlsk) < 0) {
		fprintf(stderr, "failed to send name of GENL family %s\n", name);
		goto send_nl_cmd_err;
	}

	if (recv_nl_resp(genlsk) < 0) {
		fprintf(stderr, "failed to recv ID of GENL family %s\n", name);
		goto recv_nl_resp_err;
	}

	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->buf;
	struct nlattr *nla = (struct nlattr *)GENL_DATA(nlh);
	int len = NLMSG_PAYLOAD(nlh, GENL_HDRLEN);
	if (len < sizeof NLA_HDRLEN || len < NLA_ALIGN(nla->nla_len)) {
		goto parse_faid_err;
	}
	nla = (struct nlattr *)((char *)nla + NLA_ALIGN(nla->nla_len));
	len -= NLA_ALIGN(nla->nla_len);
	if (len < sizeof NLA_HDRLEN || len < NLA_ALIGN(nla->nla_len)) {
		goto parse_faid_err;
	}
	if (nla->nla_type != CTRL_ATTR_FAMILY_ID || nla->nla_len < 2) {
		goto parse_faid_err;
	}

	genlsk->faid = *(uint16_t *)((char *)nla + NLA_HDRLEN);
	return genlsk;

parse_faid_err:
recv_nl_resp_err:
send_nl_cmd_err:
connect_err:
	close(fd);
socket_err:
	free(genlsk);
malloc_err:
	return NULL;
}

int close_genl_socket(struct genlsk *genlsk)
{
	int ret = close(genlsk->fd);
	free(genlsk);
	return ret;
}
