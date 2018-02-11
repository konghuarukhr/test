#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct route_entry {
	uint32_t network;
	uint32_t mask;
};

struct route_table {
	struct route_entry *entries;
	int size;
	int capacity;
}

static route_table *create_route_table()
{
	struct route_table *rt_tbl = calloc(1, sizeof *rt_tbl);
	if (!rt_tbl)
		return NULL;
	rt_tbl->capacity = 1;
	rt_tbl->entries = calloc(rt_tbl->capacity, sizeof *rt_tbl->entries);
	if (!rt_tbl->entries) {
		free(rt_tbl);
		return NULL;
	}
	return rt_tbl;
}


static bool route_table_need_expand(struct route_table *rt_tbl)
{
	return rt_tbl->size >= rt_tbl->capacity;
}

static bool expand_route_table(struct route_table *rt_tbl)
{
	int expand = rt_tbl->capacity * 2;
	struct route_entry *tmp = realloc(rt_tbl->entries, expand);
	if (!tmp) {
		return false;
	}
	rt_tbl->entries = tmp;
	rt_tbl->capacity = expand;
	return true;
}

static void fill_route_table(struct route_table *rt_tbl, uint32_t network,
		uint32_t mask)
{
	rt_tbl->entries[rt_tbl->size].network = network;
	rt_tbl->entries[rt_tbl->size].mask = mask;
	rt_tbl->size++;
}

static void destroy_route_table(struct route_table *rt_tbl)
{
	free(rt_tbl->entries);
	free(rt_tbl);
}

static struct route_entry *load_route_table(const char *file)
{
	struct route_table *rt_tbl = create_route_table();
	if (!rt_tbl) {
		fprintf(stderr, "failed to alloc route table\n");
		return NULL;
	}

	FILE *fp = fopen(file, "r");
	if (!fp) {
		fprintf(stderr, "failed to open file [%s]: %s\n", file,
				strerror(errno));
		return rt_tbl;
	}

	char line[32];
	char network[16];
	int mask;
	int i = 0;
	while (fscanf(fp, "%s\n", line) == 1) {
		i++;
		if (sscanf(line, "%s|%d", network, &mask) != 2) {
			fprintf(stderr, "failed to parse on line [%d]\n", i);
			continue;
		}
		struct in_addr addr;
		if (!inet_aton(network, &addr)) {
			fprintf(stderr, "failed to convert on line [%s]", i);
			continue;
		}
		if (route_table_need_expand(rt_tbl) &&
				expand_route_table(rt_tbl)) {
			fprintf(stderr, "failed to expand route table: %d\n", rt_tbl->capacity);
			return rt_tbl;
		}
		fill_route_table(rt_tbl, network, mask);
	}

	if (fclose(fp)) {
		fprintf(stderr, "failed to close file %s: %s\n", file,
				strerror(errno));
	}

	return rt_tbl;
}

bool clear_kernel_route_table(struct socket *sk)
{

}

bool restore_kernel_route_table(struct route_table *rt_tbl)
{
	int faid = get_genl_faid("IPROXY_SERVER");
	for (int i = 0; i < rt_tbl->size; i++) {
		struct route_entry *re = &rt_tbl->entries[i];
		if (send_genl_route(faid, re)) {
			fprintf(stderr, "");
		}
	}
}

int main(int argc, char *argv[])
{
	struct route_table *rt_tbl = load_route_table("");
	if (!rt_tbl) {
		fprintf(stderr, "failed to load route table, exit\n");
		goto load_route_table_err;
	}

	if (clear_kernel_route_table()) {
		fprintf(stderr, "failed to clear route table, exit\n");
		goto clear_kernel_route_table_err;
	}

	if (restore_kernel_route_table(rt_tbl)) {
		fprintf(stderr, "failed to import route table, exit\n");
		goto restore_kernel_route_table_err;
	}

	unload_route_table(rt_tbl);

	return 0;

restore_kernel_route_table_err:
	fprintf(stderr, "warning: kernel route table is cleared, but not restored, exit\n");

clear_kernel_route_table_err:
	unload_route_table(rt_tbl);

load_route_table_err:

	return -1;

}

#define GENL_LENGTH(len) NLMSG_LENGTH((len) + GENL_HDRLEN)
#define GENL_SPACE(len) NLMSG_SPACE((len) + GENL_HDRLEN)
#define GENL_DATA(nlh) (void *)((char *)NLMSG_DATA(nlh) + GENL_HDRLEN)

static struct genl_family iproxy_server_genl = {

}

struct genlsk *open_nl_socket(const char *name)
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

	struct sockaddr_nl dst;
	memset(&dst, 0, sizeof dst);
	dst.nl_family = AF_NETLINK;
	if (connect(fd, &dst, sizeof dst) < 0) {
		fprintf(stderr, "failed to connect: %s\n", strerror(errno));
		goto connect_err;
	}

	genlsk->fd = fd;
	genlsk->faid = GENL_ID_CTRL;
	genlsk->seq = 0;
	genlsk->pid = getpid();

	put_nl_hdr(genlsk);
	put_genl_hdr(genlsk, CTRL_CMD_GETFAMILY);
	put_nl_attr(genlsk, CTRL_ATTR_FAMILY_NAME, name, strlen(name) + 1);
	if (send_nl_cmd(genl) < 0) {
		fprintf(stderr, "failed to send: %s\n", strerror(errno));
		goto send_nl_cmd_err;
	}

	if (recv_nl_resp(genlsk) < 0) {
		fprintf(stderr, "failed to recv: %s\n", strerror(errno));
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

	genlsk->faid = *(uint16_t *)NLA_DATA(nla);

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

int close_nl_socket(int fd)
{
	return close(fd);
}

void put_nl_hdr(struct genlsk *genlsk)
{
	genlsk->cur = genlsk->buf;
	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->cur;
	nlh->nlmsg_type = genlsk->faid;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = ++genl->seq;
	nlh->nlmsg_pid = genl->pid;
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

void add_nl_attr(struct genlsk *genlsk, uint16_t type, const char *data,
		int len)
{
	struct nlattr *nla = (struct nlattr *)genlsk->cur;
	nla->nla_len = NLA_HDRLEN + len;
	nla->nla_type = type;
	memcpy((char *)nla + NLA_HDRLEN, data, len);
	genlsk->cur += NLA_ALIGN(nla->nla_len);
	update_nl_hdr_len(genlsk);
}

void update_nl_hdr_len(struct genlsk *genlsk)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->buf;
	nlh->nlmsg_len = genlsk->cur - genlsk->buf;
}

int send_nl_cmd(struct genlsk *genlsk)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->cur;
	int len = nlh->nlmsg_len;
	int off = 0;
	while (off < len) {
		ret = send(genlsk->fd, genlsk->buf + off, len - off, 0);
		if (off < 0) {
			fprintf(stderr, "%s\n", strerror(errno));
			return -1;
		}
		off += ret;
	}
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

	struct genlmsghdr *genlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	if ()
}

int update_nl_faid(struct genlsk *genlsk)
{
}

struct genlsk {
	char buf[BUF_SIZE];
	char *cur;
	int fd;
	uint16_t faid;
	uint32_t seq;
	uint32_t pid;
}

int get_nl_faid(int fd, unsigned int seq, unsigned int pid, const char *name)
{
	if (send_nl_attr(fd, GENL_ID_CTRL, seq, pid, CTRL_CMD_GETFAMILY,
			CTRL_ATTR_FAMILY_NAME, "", 100) < 0) {
		return -1;
	}

	char buf[BUF_SIZE];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

	struct nlattr *nla = (struct nlattr *)GENL_DATA(nlh);
	nla = (struct nlattr *)((char *)nla + NLA_ALIGN(nla->nla_len));
	if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
		id = *(uint16_t *) NLA_DATA(na);
	}
	return id;
}

int add_kernel_route(struct genlsk *genlsk, uint32_t *network, uint8_t *mask,
		uint8_t cnt)
{
	put_nl_hdr(genlsk);
	put_genl_hdr(genlh, CMD_ADD_ROUTE);
	put_genlipr_hdr(genliprh, 0, cnt);
	for (int i = 0; i < cnt; i++) {
		if (add_nl_attr(nla, ATTR_ROUTE, network, sizeof network) < 0) {
			return -1;
		}
		if (add_nl_attr(nla, ATTR_ROUTE, mask, sizeof mask) < 0) {
			return -1;
		}
	}

	if (send_nl_cmd(genlsk) < 0) {
		return -1;
	}

	if (recv_nl_resp(genlsk) < 0) {
		return -1;
	}
}

void test()
{
	char buf[4096];

	struct sockaddr_nl src;
	memset(&src, 0, sizeof src);
	src.nl_family = AF_NETLINK;
	src.nl_pid = getpid();

	struct nlmsghdr *nh;
	struct msghdr msgh;

}
