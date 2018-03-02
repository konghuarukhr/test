#define CLIENT
#include "common.h"

struct route_table *route_table = NULL;

static char *server_ip = NULL;
module_param(server_ip, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(server_ip, "server ip");
static __be32 _server_ip = 0;

static unsigned short port = 0;
module_param(port, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(port, "client & server port (UDP)");
static __be16 _port = 0;

static unsigned short user = 0;
module_param(user, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(user, "user");
static __be16 _user = 0;

static unsigned char passwd = 0;
module_param(passwd, byte, 0);
MODULE_PARM_DESC(passwd, "password");

static unsigned char dns_policy = 0;
module_param(dns_policy, byte, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(dns_policy, "0: proxy all; 1: not proxy private ip; 2: no special");
enum {
	DNS_UNSPEC,
	DNS_ALL,
	DNS_PUBLIC,
	DNS_NO_SPECIAL,
};

static unsigned char route_policy = 0;
module_param(route_policy, byte, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(route_policy, "0: get route from server; 1: route all traffic");
enum {
	ROUTE_UNSPEC,
	ROUTE_LEARN,
	ROUTE_ALL,
};

/**
 * TODO: supports multi proxies
 */
static inline bool is_server_ip(__be32 ip)
{
	return ip == _server_ip;
}

static inline __be32 get_server_ip(void)
{
	return _server_ip;
}

static inline bool is_client_port(__be16 port)
{
	return port == _port;
}

static inline __be16 get_client_port(void)
{
	return _port;
}

static inline bool is_server_port(__be16 port)
{
	return port == _port;
}

static inline __be16 get_server_port(void)
{
	return _port;
}

static inline __be16 my_get_user(void)
{
	return _user;
}

static inline unsigned char get_passwd(void)
{
	return passwd;
}

static inline bool is_dns_all(void)
{
	return dns_policy == DNS_ALL;
}

static inline bool is_dns_public(void)
{
	return dns_policy == DNS_PUBLIC;
}

static inline bool is_dns_no_special(void)
{
	return dns_policy == DNS_NO_SPECIAL;
}

static inline bool is_route_learn(void)
{
	return route_policy == ROUTE_LEARN;
}

static inline bool is_route_all(void)
{
	return route_policy == ROUTE_ALL;
}


static int params_init(void)
{
	if (server_ip != NULL)
		_server_ip = in_aton(server_ip);
	if (!_server_ip) {
		LOG_ERROR("server_ip param error");
		return -EINVAL;
	}
	_port = htons(port);
	if (!_port) {
		LOG_ERROR("port param error");
		return -EINVAL;
	}
	_user = htons(user);
	if (!_user) {
		LOG_ERROR("user param error");
		return -EINVAL;
	}
	if (passwd) {
		LOG_ERROR("passwd param error");
		return -EINVAL;
	}
	if (dns_policy) {
		LOG_ERROR("dns_policy param error");
		return -EINVAL;
	}
	if (route_policy) {
		LOG_ERROR("route_policy param error");
		return -EINVAL;
	}

	return 0;
}

static void params_uninit(void)
{
}

static int custom_init(void)
{
	int err;

	err = params_init();
	if (err) {
		LOG_ERROR("failed to init params: %d", err);
		goto params_init_err;
	}

	route_table = route_table_init();
	if (!route_table) {
		err = -ENOMEM;
		LOG_ERROR("failed to init route table: %d", err);
		goto route_table_init_err;
	}

	return 0;

route_table_init_err:
	params_uninit();

params_init_err:

	return err;
}

static void custom_uninit(void)
{
	route_table_uninit(route_table);
	params_uninit();
}

static inline bool is_dns_port(const struct udphdr *udph)
{
	return udph->dest == __constant_htons(53);
}

static inline bool is_dns_proto(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_UDP)
		if (pskb_network_may_pull(skb, sizeof(struct udphdr)))
			return is_dns_port(udp_hdr(skb));
	return false;
}

/**
 * https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
 */
static bool is_private_ip(__be32 ip)
{
	__be32 network;

	// 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8
	network = ip & __constant_htonl(0xFF000000U);
	switch (network) {
		case __constant_htonl(0x00000000U):
			return true;
		case __constant_htonl(0x0A000000U):
			return true;
		case __constant_htonl(0x7F000000U):
			return true;
	}

	// 100.64.0.0/10
	network = ip & __constant_htonl(0xFFC00000U);
	if (network == __constant_htonl(0x64400000U))
		return true;

	// 172.16.0.0/12
	network = ip & __constant_htonl(0xFFF00000U);
	if (network == __constant_htonl(0xAC100000U))
		return true;

	// 192.168.0.0/16
	network = ip & __constant_htonl(0xFFFF0000U);
	if (network == __constant_htonl(0xC0A80000U))
		return true;

	return false;
}

static bool is_noproxy_ip(__be32 ip)
{
	return route_table_contains(route_table, ip);
}

static bool need_client_encap(struct sk_buff *skb)
{
	struct iphdr *iph;

	iph = ip_hdr(skb);

    LOG_INFO("ip: %pI4, server ip: %pI4", &iph->daddr, &_server_ip);
	if (is_server_ip(iph->daddr))
		return false;

	if (!is_dns_no_special() && is_dns_proto(skb)) {
		if (is_dns_all())
			return true;
		if (is_dns_public() && !is_private_ip(iph->daddr))
			return true;
		return false;
	}

	if (is_private_ip(iph->daddr))
		return false;

	if (is_route_learn() && is_noproxy_ip(iph->daddr))
		return false;

	LOG_INFO("need_client_encap: %pI4 -> %pI4", &iph->saddr, &iph->daddr);
	return true;
}

static int do_client_encap(struct sk_buff *skb)
{
	int err;
	struct iphdr *iph, *niph;
	struct udphdr *udph;
	struct iprhdr *iprh;
	int nhl;
    __u8 *sum;


	err = skb_cow(skb, CAPL);
	if (err) {
		LOG_ERROR("failed to do skb_cow: %d", err);
		return err;
	}

	nhl = skb_network_header_len(skb);

    //LOG_INFO("before pull: %d", skb->len);
	__skb_pull(skb, nhl);
    //LOG_INFO("after pull: %d", skb->len);
	masq_data(skb, get_passwd());

	iph = ip_hdr(skb);
    //LOG_INFO("csum: calc3 0x%x", csum_tcpudp_magic(iph->saddr, iph->daddr, ntohs(iph->tot_len) -nhl, iph->protocol, 0));
	niph = (struct iphdr *)__skb_push(skb, nhl + CAPL);
    //LOG_INFO("after push: %d", skb->len);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	iprh = ipr_hdr(skb);
	iprh->type = IPR_C_S;
	iprh->protocol = niph->protocol;
	iprh->user = my_get_user();
	iprh->ip = niph->daddr;

	udph = udp_hdr(skb);
	udph->source = get_client_port();
	udph->dest = get_server_port();
	udph->len = htons(ntohs(niph->tot_len) + CAPL - nhl);
	udph->check = 0;

	niph->protocol = IPPROTO_UDP;
	niph->daddr = get_server_ip();
	niph->tot_len = htons(ntohs(niph->tot_len) + CAPL);
	niph->check = 0;
	niph->check = ip_fast_csum(niph, niph->ihl);

    LOG_INFO("csum: ip_summed 0x%x", skb->ip_summed);
    if (skb->ip_summed == 3)
        LOG_INFO("csum: csum_offset checksum 0x%x", *(__be16 *)((skb->csum_start+skb->head)+skb->csum_offset));
    LOG_INFO("csum: csum 0x%x", skb->csum);
    /*
    LOG_INFO("csum: head %p", skb->head);
    LOG_INFO("csum: csum_start 0x%x", skb->csum_start);
    LOG_INFO("csum: csum_start offset 0x%x", skb_checksum_start_offset(skb));
    LOG_INFO("csum: csum_offset 0x%x", skb->csum_offset);
    LOG_INFO("csum: calc 0x%x", 0xffff&~csum_tcpudp_magic(niph->saddr, niph->daddr, ntohs(niph->tot_len) - CAPL - nhl, iprh->protocol, 0));
    LOG_INFO("csum: calc2 0x%x", 0xffff&~csum_tcpudp_magic(niph->saddr, iprh->ip, ntohs(niph->tot_len) -CAPL-nhl, iprh->protocol, 0));
    LOG_INFO("ffff %pI4  %pI4", &niph->saddr, &iprh->ip);
    LOG_INFO("csum: csum len 0x%x", skb->len - skb_transport_offset(skb));
    LOG_INFO("csum: csum len0 0x%x", ntohs(niph->tot_len) );
    LOG_INFO("csum: csum len0 0x%x", (int)CAPL );
    LOG_INFO("csum: csum len0 0x%x", nhl );
    LOG_INFO("csum: csum len2 0x%x", ntohs(niph->tot_len )- (int)CAPL-nhl);
    */
    LOG_INFO("protocol: %d", iprh->protocol);
	switch (iprh->protocol) {
		case IPPROTO_UDP:
            sum = skb_transport_header(skb) + sizeof(struct udphdr) + sizeof(struct iprhdr) + offsetof(struct udphdr, check);
            if (!*(__sum16 *)sum && skb->ip_summed != CHECKSUM_PARTIAL)
                break;
            if (sum - skb->data >= skb_headlen(skb)) {
                LOG_ERROR("UDP checksum offset exceed skb head length");
                return -EFAULT;
            }
			inet_proto_csum_replace4((__sum16 *)sum, skb, niph->saddr, 0, true);
            if (!*(__sum16 *)sum)
                *(__sum16 *)sum = CSUM_MANGLED_0;
			break;
		case IPPROTO_UDPLITE:
            sum = skb_transport_header(skb) + sizeof(struct udphdr) + sizeof(struct iprhdr) + offsetof(struct udphdr, check);
            if (sum - skb->data >= skb_headlen(skb)) {
                LOG_ERROR("UDPLITE checksum offset exceed skb head length");
                return -EFAULT;
            }
			inet_proto_csum_replace4((__sum16 *)sum, skb, niph->saddr, 0, true);
			break;
		case IPPROTO_TCP:
            sum = skb_transport_header(skb) + sizeof(struct udphdr) + sizeof(struct iprhdr) + offsetof(struct tcphdr, check);
            if (sum - skb->data >= skb_headlen(skb)) {
                LOG_ERROR("TCP checksum offset exceed skb head length");
                return -EFAULT;
            }
			inet_proto_csum_replace4((__sum16 *)sum, skb, niph->saddr, 0, true);
			break;
		case IPPROTO_DCCP:
            sum = skb_transport_header(skb) + sizeof(struct udphdr) + sizeof(struct iprhdr) + offsetof(struct dccp_hdr, dccph_checksum);
            if (sum - skb->data >= skb_headlen(skb)) {
                LOG_ERROR("DCCP checksum offset exceed skb head length");
                return -EFAULT;
            }
			inet_proto_csum_replace4((__sum16 *)sum, skb, niph->saddr, 0, true);
			break;
	}
    LOG_INFO("csum: csum_offset checksum 0x%x", *(__be16 *)((skb->csum_start+skb->head)+skb->csum_offset));

	return 0;
}

static bool need_client_decap(struct sk_buff *skb) {
	struct iphdr *iph;
	struct udphdr *udph;
	struct iprhdr *iprh;

	iph = ip_hdr(skb);
	if (!is_server_ip(iph->saddr))
		return false;

	if (iph->protocol != IPPROTO_UDP)
		return false;

	/* skb is defraged by nf_defrag_ipv4 */
	if (!pskb_network_may_pull(skb, CAPL))
		return false;

	udph = udp_hdr(skb);
	if (!is_server_port(udph->source))
		return false;

	iprh = ipr_hdr(skb);
	if (!is_ipr_sc(iprh))
		return false;

	LOG_INFO("need_client_decap: %pI4 -> %pI4", &iph->saddr, &iph->daddr);
	return true;
}

static unsigned int do_client_decap(struct sk_buff *skb)
{
	int nhl;
	struct iphdr *iph, *niph;
	struct iprhdr *iprh;

	nhl = skb_network_header_len(skb);

	iph = ip_hdr(skb);
	iprh = ipr_hdr(skb);

	iph->protocol = iprh->protocol;
	iph->saddr = iprh->ip;
	iph->tot_len = htons(ntohs(iph->tot_len) - CAPL);
	//iph->check = ;

	niph = (struct iphdr *)__skb_pull(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	__skb_pull(skb, nhl);
	demasq_data(skb, get_passwd());
	__skb_push(skb, nhl);

	return 0;
}

static unsigned int client_encap(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	if (!need_client_encap(skb))
		return NF_ACCEPT;

	if (do_client_encap(skb))
		return NF_DROP;

	return NF_ACCEPT;
}

static unsigned int client_decap(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	if (!need_client_decap(skb))
		return NF_ACCEPT;

	if (do_client_decap(skb))
		return NF_DROP;

	return NF_ACCEPT;
}

static const struct nf_hook_ops iproxy_nf_ops[] = {
	{
		.hook = client_encap,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = client_encap,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = client_decap,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST,
	},
};

enum {
	IPRCA_NETWORK,
	IPRCA_MASK,
	__IPRCA_MAX,
};
#define IPRCA_MAX (__IPRCA_MAX - 1)

enum {
	IPRCC_CLEAR_ROUTE,
	IPRCC_ADD_ROUTE,
	IPRCC_DELETE_ROUTE,
	IPRCC_SHOW_ROUTE,
	__IPRCC_MAX,
};
#define IPRCC_MAX (__IPRCC_MAX - 1)

static struct nla_policy iproxy_genl_policy[IPRCA_MAX + 1] = {
	[IPRCA_NETWORK] = {.type = NLA_U32},
	[IPRCA_MASK] = {.type = NLA_U8},
};

static int clear_route(struct sk_buff *skb, struct genl_info *info)
{
	route_table_clear(route_table);
	return 0;
}

static int add_route(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *network_attr = info->attrs[IPRCA_NETWORK];
	struct nlattr *mask_attr = info->attrs[IPRCA_MASK];
	if (network_attr && mask_attr) {
		__be32 network = nla_get_be32(network_attr);
		__u8 mask = nla_get_u8(mask_attr);
		route_table_add(route_table, network, mask);
		return 0;
	}
	return -EINVAL;
}

static int delete_route(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *network_attr = info->attrs[IPRCA_NETWORK];
	struct nlattr *mask_attr = info->attrs[IPRCA_MASK];
	if (network_attr && mask_attr) {
		__be32 network = nla_get_be32(network_attr);
		__u8 mask = nla_get_u8(mask_attr);
		route_table_delete(route_table, network, mask);
		return 0;
	}
	return -EINVAL;
}

static int show_route(struct sk_buff *skb, struct genl_info *info)
{
	return -ENOTSUPP;
}

static const struct genl_ops iproxy_genl_ops[] = {
	{
		.cmd = IPRCC_CLEAR_ROUTE,
		.doit = clear_route,
	},
	{
		.cmd = IPRCC_ADD_ROUTE,
		.doit = add_route,
		.policy = iproxy_genl_policy,
	},
	{
		.cmd = IPRCC_DELETE_ROUTE,
		.doit = delete_route,
		.policy = iproxy_genl_policy,
	},
	{
		.cmd = IPRCC_SHOW_ROUTE,
		.doit = show_route,
	},
};

static struct genl_family iproxy_genl_family = {
	.hdrsize = 0,
	.name = "IPROXY-CLIENT",
	.version = 0x01,
	.maxattr = IPRCA_MAX,
	.netnsok = true,
	.ops = iproxy_genl_ops,
	.n_ops = ARRAY_SIZE(iproxy_genl_ops),
	.module = THIS_MODULE,
};

#include "module.i"
