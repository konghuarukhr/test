#include "common.h"

static char *server_ip = NULL;
module_param(server_ip, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(server_ip, "server ip");
static __be32 _server_ip = 0;

static unsigned short server_port = 0;
module_param(server_port, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(server_port, "server port (UDP)");
static __be16 _server_port = 0;

static char *client_ip_start = NULL;
module_param(client_ip_start, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(client_ip_start, "fake client ip start from");
static u32 _client_ip_start = 0;

static unsigned int client_ip_number = 0;
module_param(client_ip_number, uint, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(client_ip_number, "fake client ip total number");

static char *dns_ip = NULL;
module_param(dns_ip, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(dns_ip, "dns ip");
static __be32 _dns_ip = 0;

static int param_init(void)
{
	if (server_ip != NULL)
		_server_ip = in_aton(server_ip);
	if (_server_ip == 0) {
		LOG_ERROR("server_ip param error");
		return -EINVAL;
	}

	if (server_port != 0)
		_server_port = htons(server_port);
	if (_server_port != 0) {
		LOG_ERROR("server_port param error");
		return -EINVAL;
	}

	if (client_ip_start != NULL)
		_client_ip_start = ntohl(in_aton(client_ip_start));
	if (_client_ip_start == 0) {
		LOG_ERROR("client_ip_start param error");
		return -EINVAL;
	}

	if (client_ip_number == 0) {
		LOG_ERROR("client_ip_number param error");
		return -EINVAL;
	}

	if (dns_ip != NULL)
		_dns_ip = in_aton(dns_ip);
	if (_dns_ip == 0) {
		LOG_ERROR("dns_ip param error");
		return -EINVAL;
	}

	return 0;
}

static inline __be32 get_server_ip(void)
{
	return _server_ip;
}

static inline __be16 get_server_port(void)
{
	return _server_port;
}

static DECLARE_BITMAP(client_ip_used_map, client_ip_number);
static client_ip_unused_idx = 0;

__be32 apply_ip(void)
{
	client_ip_unused_idx = find_next_zero_bit(client_ip_used_map,
			client_ip_number, client_ip_unused_idx);
	if (client_ip_unused_idx == client_ip_number) {
		return 0;
	}
	set_bit(client_ip_unused_idx, client_ip_used_map);
	client_ip_unused_idx++;
	return htonl(_client_ip_start + client_ip_unused_idx);
}

void release_ip(__be32 ip)
{
	client_ip_unused_idx = ntohl(ip) - _client_ip_start;
	clear_bit(client_ip_unused_idx, client_ip_used_map);
}

static inline __be32 get_dns_ip(void)
{
	return _dns_ip;
}

struct xlate_entry {
	__be32 saddr;
	__be16 source;
	__be16 user;
	__be32 daddr;
	struct hlist_node fnode;
	struct hlist_node bnode;
};
static struct forward_xlate_htbl;
static struct backward_xlate_htbl;

struct xlate_entry *lookup_xlate_entry(__be32 saddr, __be16 source,
		__be16 user, )
{
	struct xlate_entry *xe;
	__be64 key = ((__be64)source << 32) + saddr;
	hash_for_each_possible(forward_xlate_htbl, xe, fnode, key)
		if (xe->saddr == saddr && xe->source == source)
			return xe;
	xe = kmalloc(sizeof *xe, GFP_KERNEL);
	if (xe == NULL) {
		LOG_ERROR("failed to alloc xlate entry memory");
		return -ENOMEM;
	}
	xe->saddr = saddr;
	xe->source = source;
	xe->user = user;
	xe->daddr = release;
	if (xe->daddr == 0) {
		LOG_ERROR("failed to alloc xlate entry memory");
		kfree(xe);
		return -ENOENT;
	}

	hash_add(forward_xlate_htbl, &xe->fnode, key);
	hash_add(backward_xlate_htbl, &xe->bnode, key);
}





static bool need_server_decap(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	if (!is_server_ip(iph->daddr))
		return false;
	if (iph->protocol != IPPROTO_UDP)
		return false;

	if (!pskb_may_pull_iprhdr(skb))
		return false;

	struct udphdr *udph = udp_hdr(skb);
	if (!is_server_port(udph->dest))
		return false;

	struct iprhdr *iprh = ipr_hdr(skb);
	if (!is_client_to_server(iprh))
		return false;

	return true;
}

static int do_server_decap(struct sk_buff *skb)
{
	int nhl = skb_network_header_len(skb);
	struct iphdr *iph = ip_hdr(skb);
	struct udphdr *udph = udp_hdr(skb);
	struct iprhdr *iprh = ipr_hdr(skb);

	__be16 user = iprh->user;

	struct xlate_entry *xe = lookup_xlate_entry(iph->saddr, udph->source,
			user);
	if (xe == NULL) {
		LOG_ERROR("failed to lookup xlate entry");
		return -ENOENT;
	}

	iph->saddr = xe->daddr;
	iph->daddr = iprh->daddr;
	iph->tot_len = htons(ntohs(iph->tot_len) - CAPL);
	//iph->check = ;

	void *niph = __skb_pull(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	__skb_pull(skb, nhl);
	demasq_data(skb, get_passwd(user));
	__skb_push(skb, nhl);

	return 0;
}

static bool need_server_encap(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct xlate_entry *xe = get_xlate_entry(iph->daddr);
	if (xe == NULL)
		return false;

	return true;
}

static int do_server_encap(struct sk_buff *skb)
{
	int err;

	if (err = skb_cow(skb, CAPL))
		return err;

	int nhl = skb_network_header_len(skb);

	__skb_pull(skb, nhl);
	masq_data(skb);

	struct iphdr *iph = ip_hdr(skb);
	void *niph = __skb_push(skb, nhl + CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	struct xlate_entry *xe = get_xlate_entry(niph->daddr);

	struct iprhdr *iprh = ipr_hdr(skb);
	iprh->type = IPR_S_C;
	iprh->user = xe->user;
	iprh->addr = niph->saddr;

	struct udphdr *udph = udp_hdr(skb);
	udph->source = get_server_port();
	udph->dest = xe->sport;
	udph->len = htons(ntohs(niph->tot_len) + CAPL - nhl);
	udph->check = 0;

	niph->saddr = get_server_ip();
	niph->daddr = xe->sip;
	niph->tot_len = htons(ntohs(niph->tot_len) + CAPL);
	//niph->check = ;

	return 0;
}

static unsigned int server_decap(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	if (!need_server_decap(skb))
		return NF_ACCEPT;

	if (do_server_decap(skb))
		return NF_DROP;

	return NF_ACCEPT;
}

static unsigned int server_encap(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	if (!need_server_encap(skb))
		return NF_ACCEPT;

	if (do_server_encap(skb))
		return NF_DROP;

	return NF_ACCEPT;
}

static const struct nf_hook_ops iproxy_nf_ops[] = {
	{
		.hook = server_decap,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST,
	},
	{
		.hook = server_encap,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
};

static void iproxy_nl_input(struct sk_buff *skb)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh = NULL;
	u8 *data = NULL;
	nlh = nlmsg_hdr(skb);

	while ((skb = skb_dequeue(&sk->receive_queue)) 
			!= NULL) {
		/* process netlink message pointed by skb->data */
		nlh = (struct nlmsghdr *)skb->data;
		data = NLMSG_DATA(nlh);
		/* process netlink message with header pointed by 
		 * nlh and data pointed by data
		 */
}

static struct netlink_kernel_cfg iproxy_nl_cfg = {
	.input = iproxy_nl_input;
};

int import_route(struct sk_buff *skb, struct genl_info *info)
{
}

enum {
	IMPORT_ROUTE,
};

enum {
	XX
};

static struct nla_policy iproxy_genl_policy[] = {
	[IMPORT_ROUTE] = {},
}

static const struct genl_ops iproxy_genl_ops[] = {
	{
		.cmd = IMPORT_ROUTE,
		.doit = import_route,
	},
}

static struct genl_family iproxy_genl_family = {
	.hdrsize = 0,
	.name = "IPROXY",
	.version = 0x01,
	.maxattr = SMC_PNETID_MAX,
	.netnsok = true,
	.ops = iproxy_genl_ops,
	.n_ops = ARRAY_SIZE(iproxy_genl_ops),
	.module = THIS_MODULE,
};


#include "module.i"
