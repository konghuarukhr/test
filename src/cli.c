#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "genl.h"


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
	struct genlsk *genlsk = open_genl_socket("IPROXY_SERVER");
	if (!genlsk) {
		return false;
	}


	close_genl_socket(genlsk);
	return true;
}

bool restore_kernel_route_table(struct route_table *rt_tbl)
{
	struct genlsk *genlsk = open_genl_socket("IPROXY_SERVER");
	if (!genlsk) {
		return false;
	}

	for (int i = 0; i < rt_tbl->size; i++) {
		struct route_entry *re = &rt_tbl->entries[i];
		if (add_kernel_route(genlsk, re->network, re->mask) < 0) {
			return false;
		}
	}

	close_genl_socket(genlsk);
	return true;
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



int add_kernel_route(struct genlsk *genlsk, uint32_t network, uint8_t mask)
{
	put_nl_hdr(genlsk);
	put_genl_hdr(genlh, CMD_ADD_ROUTE);
	if (add_nl_attr(nla, ATTR_NETWORK, network, sizeof network) < 0) {
		return -1;
	}
	if (add_nl_attr(nla, ATTR_MASK, mask, sizeof mask) < 0) {
		return -1;
	}

	if (send_nl_cmd(genlsk) < 0) {
		return -1;
	}

	if (recv_nl_resp(genlsk) < 0) {
		return -1;
	}

	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->buf;
	struct genliprhdr *genliprh = (struct genliprhdr *)GENL_DATA(nlh);
	int len = NLMSG_PAYLOAD(nlh, GENL_HDRLEN);
	if (len < GENLIPR_HDRLEN) {
		return -1;
	}
	if (genliprh->type != SUCCESS)
		return -1;
	return 0;
}

int clear_all_kernel_route(struct genlsk *genlsk)
{
	put_nl_hdr(genlsk);
	put_genl_hdr(genlh, CMD_CLEAR_ROUTE);

	if (send_nl_cmd(genlsk) < 0) {
		return -1;
	}

	if (recv_nl_resp(genlsk) < 0) {
		return -1;
	}

	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->buf;
	struct genliprhdr *genliprh = (struct genliprhdr *)GENL_DATA(nlh);
	int len = NLMSG_PAYLOAD(nlh, GENL_HDRLEN);
	if (len < GENLIPR_HDRLEN) {
		return -1;
	}
	if (genliprh->type != SUCCESS)
		return -1;
	return 0;
}
