#define SERVER
#include "common.h"

#define VIP_EXPIRE 600

struct xlate_table *xlate_table = NULL;

static char *server_ip = NULL;
module_param(server_ip, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(server_ip, "server ip");
static __be32 _server_ip = 0;

static unsigned short server_port = 0;
module_param(server_port, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(server_port, "server port (UDP)");
static __be16 _server_port = 0;

static char *vip_start = NULL;
module_param(vip_start, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(vip_start, "virtual client ip start from (10.0.0.0)");
static __u32 _vip_start = 0;

static unsigned int vip_number = 0;
module_param(vip_number, uint, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(vip_number, "virtual client ip total number (1024)");

static char *dns_ip = NULL;
module_param(dns_ip, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(dns_ip, "dns ip");
static __be32 _dns_ip = 0;

static unsigned char get_passwd(__be16 user)
{
	return 0;
}

static int params_init(void)
{
	if (server_ip != NULL)
		_server_ip = in_aton(server_ip);
	if (_server_ip == 0) {
		LOG_ERROR("server_ip param error");
		return -EINVAL;
	}

	if (server_port != 0)
		_server_port = htons(server_port);
	if (_server_port == 0) {
		LOG_ERROR("server_port param error");
		return -EINVAL;
	}

	if (vip_start != NULL)
		_vip_start = ntohl(in_aton(vip_start));
	if (_vip_start == 0) {
		LOG_ERROR("vip_start param error");
		return -EINVAL;
	}

	if (!vip_number) {
		LOG_ERROR("vip_number param error");
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

static void params_uninit(void)
{
}

struct route_table *route_table;
static int custom_init(void)
{
	int err;

	err = params_init();
	if (err) {
		LOG_ERROR("failed to init input params: %d", err);
		return err;
	}

	route_table = route_table_init();
	if (!route_table) {
		LOG_ERROR("failed to init route table");
		return -ENOMEM;
	}

	xlate_table = xlate_table_init(_vip_start, vip_number, VIP_EXPIRE);
	if (!xlate_table) {
		LOG_ERROR("failed to init xlate table");
		return -ENOMEM;
	}

	return 0;
}

static void custom_uninit(void)
{
	params_uninit();
}

static inline __be32 get_server_ip(void)
{
	return _server_ip;
}

static inline __be16 get_server_port(void)
{
	return _server_port;
}

static inline __be32 get_dns_ip(void)
{
	return _dns_ip;
}


/**
 * TODO: supports multi proxies
 */
static bool is_server_ip(__be32 ip)
{
	return ip == _server_ip;
}

static bool is_server_port(__be16 port)
{
	return port == _server_port;
}

static bool need_server_decap(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct udphdr *udph;
	struct iprhdr *iprh;

	iph = ip_hdr(skb);
	if (!is_server_ip(iph->daddr))
		return false;
	if (iph->protocol != IPPROTO_UDP)
		return false;

	LOG_INFO("decap: %pI4 -> %pI4", &iph->saddr, &iph->daddr);
	LOG_INFO("decap: skb len %u", skb->len);

	if (!pskb_may_pull_iprhdr(skb))
		return false;

	udph = udp_hdr(skb);
	if (!is_server_port(udph->dest))
		return false;

	iprh = ipr_hdr(skb);
	if (!is_ipr_cs(iprh))
		return false;

	LOG_INFO("need_server_decap: %pI4 -> %pI4", &iph->saddr, &iph->daddr);
	return true;
}

static int do_server_decap(struct sk_buff *skb)
{
	int err;
	int nhl;
	struct iphdr *iph, *niph;
	struct udphdr *udph;
	struct iprhdr *iprh;
	__be32 xvip;
	__be16 user;
	struct tcphdr *tcph;
	struct dccp_hdr *dccph;

	nhl = skb_network_header_len(skb);

	iph = ip_hdr(skb);
	udph = udp_hdr(skb);
	iprh = ipr_hdr(skb);

	user = iprh->user;

	LOG_INFO("xlate: ip %pI4 port %u", &iph->saddr, ntohs(udph->source));
	LOG_INFO("xlate: skb len %u", skb->len);
	err = xlate_table_lookup_vip(xlate_table, iph->saddr, udph->source,
			user, &xvip);
	if (err) {
		LOG_ERROR("failed to lookup xlate vip: %d", err);
		return err;
	}
	LOG_INFO("xlate: vip %pI4", &xvip);

	iph->protocol = iprh->protocol;
	iph->saddr = xvip;
	iph->daddr = iprh->ip;
	iph->tot_len = htons(ntohs(iph->tot_len) - CAPL);
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	niph = (struct iphdr *)__skb_pull(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	__skb_pull(skb, nhl);
//	LOG_INFO("before data: %x", *(__u8 *)skb->data);
	demasq_data(skb, get_passwd(user));
//	LOG_INFO("after data: %x", *(__u8 *)skb->data);
	__skb_push(skb, nhl);
	/*
    LOG_INFO("csum: ip_summed 0x%x", skb->ip_summed);
    LOG_INFO("csum: csum 0x%x", skb->csum);
    LOG_INFO("csum: head %p", skb->head);
    LOG_INFO("csum: csum_start 0x%x", skb->csum_start);
    LOG_INFO("csum: csum_start offset 0x%x", skb_checksum_start_offset(skb));
    LOG_INFO("csum: csum_offset 0x%x", skb->csum_offset);
    LOG_INFO("csum: csum_offset checksum 0x%x", *(__be16 *)((skb->csum_start+skb->head)+skb->csum_offset));
    LOG_INFO("csum: calc 0x%x", 0xffff&~csum_tcpudp_magic(niph->saddr, niph->daddr, ntohs(niph->tot_len) - nhl, niph->protocol, 0));
    LOG_INFO("csum: calc2 0x%x", 0xffff&~csum_tcpudp_magic(0x0F02000A, 0x08080808, ntohs(niph->tot_len) - nhl, niph->protocol, 0));
    LOG_INFO("csum: csum len 0x%x", skb->len - skb_transport_offset(skb));
    LOG_INFO("csum: csum len0 0x%x", ntohs(niph->tot_len) );
    LOG_INFO("csum: csum len0 0x%x", (int)CAPL );
    LOG_INFO("csum: csum len0 0x%x", nhl );
    LOG_INFO("csum: csum len2 0x%x", ntohs(niph->tot_len ) - nhl);
    */
    //inet_proto_csum_replace4((__sum16 *)(skb->csum_start+skb->head+skb->csum_offset), skb, iprh->ip, niph->daddr, true);
//    LOG_INFO("csum: csum_offset checksum 0x%x", *(__be16 *)((skb->csum_start+skb->head)+skb->csum_offset));
	switch (niph->protocol) {
		case IPPROTO_UDP:
			udph = udp_hdr(skb);
			if (!udph->check)
				break;
			csum_replace4(&udph->check, 0, xvip);
			skb->ip_summed = CHECKSUM_NONE;
			break;
		case IPPROTO_UDPLITE:
			udph = udp_hdr(skb);
			csum_replace4(&udph->check, 0, xvip);
			skb->ip_summed = CHECKSUM_NONE;
			break;
		case IPPROTO_TCP:
			tcph = tcp_hdr(skb);
			csum_replace4(&tcph->check, 0, xvip);
			skb->ip_summed = CHECKSUM_NONE;
			break;
		case IPPROTO_DCCP:
			dccph = dccp_hdr(skb);
			csum_replace4(&dccph->dccph_checksum, 0, xvip);
			skb->ip_summed = CHECKSUM_NONE;
			break;
	}

	return 0;
}

static bool need_server_encap(struct sk_buff *skb)
{
	struct iphdr *iph;
	__u32 ip;

	iph = ip_hdr(skb);
	ip = ntohl(iph->daddr);
	if (ip < _vip_start || ip >= _vip_start + vip_number)
		return false;

	LOG_INFO("need_server_encap: %pI4 -> %pI4", &iph->saddr, &iph->daddr);
	return true;
}

static int do_server_encap(struct sk_buff *skb)
{
	int err;
	int nhl;
	__be32 xip;
	__be16 xport;
	__be16 xuser;
	struct iphdr *iph, *niph;
	struct udphdr *udph;
	struct iprhdr *iprh;

	iph = ip_hdr(skb);
	LOG_INFO("xlate: vip %pI4", &iph->daddr);
	err = xlate_table_find_ipport(xlate_table, iph->daddr, &xip, &xport,
			&xuser);
	if (err) {
		LOG_ERROR("failed to find xlate ipport: %d", err);
		return err;
	}
	LOG_INFO("xlate: ip %pI4 port %u", &xip, ntohs(xport));

	err = skb_cow(skb, CAPL);
	if (err) {
		LOG_ERROR("failed to do skb_cow: %d", err);
		return err;
	}

	nhl = skb_network_header_len(skb);

	__skb_pull(skb, nhl);
	masq_data(skb, get_passwd(xuser));

	iph = ip_hdr(skb);
	niph = (struct iphdr *)__skb_push(skb, nhl + CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	iprh = ipr_hdr(skb);
	iprh->type = IPR_S_C;
	iprh->protocol = niph->protocol;
	iprh->user = xuser;
	iprh->ip = niph->saddr;

	udph = udp_hdr(skb);
	udph->source = get_server_port();
	udph->dest = xport;
	udph->len = htons(ntohs(niph->tot_len) + CAPL - nhl);
	udph->check = 0;

	LOG_INFO("XXXX: %pI4 -> %pI4", &niph->saddr, &niph->daddr);
	niph->protocol = IPPROTO_UDP;
	niph->saddr = get_server_ip();
	niph->daddr = xip;
	niph->tot_len = htons(ntohs(niph->tot_len) + CAPL);
	niph->check = 0;
	niph->check = ip_fast_csum(niph, niph->ihl);
	LOG_INFO("YYYY: %pI4 -> %pI4", &niph->saddr, &niph->daddr);

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
		.priority = NF_IP_PRI_CONNTRACK_DEFRAG + 1,
	},
	{
		.hook = server_encap,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
};

#if 0
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
}
#endif

enum {
	IPRSA_NETWORK,
	IPRSA_MASK,
	__IPRSA_MAX,
};
#define IPRSA_MAX (__IPRSA_MAX - 1)

enum {
	IPRSC_CLEAR_ROUTE,
	IPRSC_ADD_ROUTE,
	IPRSC_DELETE_ROUTE,
	IPRSC_SHOW_ROUTE,
	__IPRSC_MAX,
};
#define IPRSC_MAX (__IPRSC_MAX - 1)

static struct nla_policy iproxy_genl_policy[IPRSA_MAX + 1] = {
	[IPRSA_NETWORK] = {.type = NLA_U32},
	[IPRSA_MASK] = {.type = NLA_U8},
};

int clear_route(struct sk_buff *skb, struct genl_info *info)
{
	return 0;
}

int add_route(struct sk_buff *skb, struct genl_info *info)
{
	/*
	struct nlattr *attr = info->attrs[IPRSA_NETWORK];
	if (attr) {
		u32 network = nla_get_u32(attr);
		return network;
	}
	*/
	return 0;
}


static const struct genl_ops iproxy_genl_ops[] = {
	{
		.cmd = IPRSC_CLEAR_ROUTE,
		.doit = clear_route,
	},
	{
		.cmd = IPRSC_ADD_ROUTE,
		.doit = add_route,
		.policy = iproxy_genl_policy,
	},
};

static struct genl_family iproxy_genl_family = {
	.hdrsize = 0,
	.name = "IPROXY_SERVER",
	.version = 0x01,
	.maxattr = IPRSA_MAX,
	.netnsok = true,
	.ops = iproxy_genl_ops,
	.n_ops = ARRAY_SIZE(iproxy_genl_ops),
	.module = THIS_MODULE,
};


#include "module.i"
