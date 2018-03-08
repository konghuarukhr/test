#include "common.h"
#include "kgenl.h"

static char *server_ip = NULL;
module_param(server_ip, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(server_ip, "server IP");
static __be32 _server_ip = 0;

static unsigned short port = 0;
module_param(port, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(port, "client/server UDP port");
static __be16 _port = 0;

static unsigned short user = 0;
module_param(user, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(user, "user");
static __be16 _user = 0;

static unsigned char password = 0;
module_param(password, byte, 0);
MODULE_PARM_DESC(password, "password");

static unsigned char dns_policy = 0;
module_param(dns_policy, byte, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(dns_policy, "0: proxy all; 1: not proxy private IP; 2: no special");
enum {
	DNS_ALL,
	DNS_PUBLIC,
	DNS_NO_SPECIAL,
	DNS_POLICY_MAX
};

static unsigned char route_policy = 0;
module_param(route_policy, byte, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(route_policy, "0: route proxy traffic; 1: route all traffic");
enum {
	ROUTE_PROXY,
	ROUTE_ALL,
	ROUTE_POLICY_MAX
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

static inline unsigned char get_password(void)
{
	return password;
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

static inline bool is_route_proxy(void)
{
	return route_policy == ROUTE_PROXY;
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

	if (dns_policy >= DNS_POLICY_MAX) {
		LOG_ERROR("dns_policy param error");
		return -EINVAL;
	}

	if (route_policy >= ROUTE_POLICY_MAX) {
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

static inline bool is_noproxy_ip(__be32 ip)
{
	return route_table_get_mask(route_table, ip);
}

static inline __be32 get_network(__be32 ip, unsigned char mask)
{
	return ip & -(1 << (32 - mask));
}

static bool need_client_encap(struct sk_buff *skb)
{
	int nhl;
	struct iphdr *iph;

	nhl = skb_network_header_len(skb);

	iph = ip_hdr(skb);
	if (is_server_ip(iph->daddr))
		return false;

	if (!is_dns_no_special() && iph->protocol == IPPROTO_UDP &&
			pskb_may_pull(skb, nhl + sizeof(struct udphdr)) &&
			is_dns_port(udp_hdr(skb))) {
		iph = ip_hdr(skb);
		if (is_dns_all()) {
			LOG_DEBUG("%pI4 -> %pI4: yes, dns all", &iph->saddr,
					&iph->daddr);
			return true;
		}
		if (is_dns_public() && !is_private_ip(iph->daddr)) {
			LOG_DEBUG("%pI4 -> %pI4: yes, dns public", &iph->saddr,
					&iph->daddr);
			return true;
		}
		return false;
	}

	if (is_private_ip(iph->daddr))
		return false;

	if (is_route_proxy() && is_noproxy_ip(iph->daddr))
		return false;

	LOG_DEBUG("%pI4 -> %pI4: yes", &iph->saddr, &iph->daddr);
	return true;
}

static int do_client_encap(struct sk_buff *skb)
{
	int err;
	int nhl;
	struct iphdr *iph, *niph;
	struct udphdr *udph;
	struct iprhdr *iprh;
	__be32 sip;
	__u8 *sum;


	err = skb_cow(skb, CAPL);
	if (err) {
		LOG_ERROR("failed to do skb_cow: %d", err);
		return err;
	}

	nhl = skb_network_header_len(skb);

	__skb_pull(skb, nhl);
	masq_data(skb, get_password());

	iph = ip_hdr(skb);
	LOG_DEBUG("%pI4 -> %pI4: encap", &iph->saddr, &iph->daddr);
	niph = (struct iphdr *)__skb_push(skb, nhl + CAPL);
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

	if (skb->ip_summed == 3)
		LOG_INFO("csum: csum_offset checksum 0x%x", *(__be16 *)((skb->csum_start+skb->head)+skb->csum_offset));
	LOG_INFO("csum: csum 0x%x", skb->csum);

	sip = niph->saddr;
	LOG_DEBUG("protocol %u ip_summed %u", iprh->protocol, skb->ip_summed);
	switch (iprh->protocol) {
		case IPPROTO_UDP:
			if (!pskb_may_pull_iprhdr_ext(skb, sizeof(struct udphdr))) {
				LOG_ERROR("UDP header offset exceed");
				return -EFAULT;
			}
			sum = skb_transport_header(skb) + CAPL + offsetof(struct udphdr, check);
			if (!*(__sum16 *)sum && skb->ip_summed != CHECKSUM_PARTIAL)
				break;
			inet_proto_csum_replace4((__sum16 *)sum, skb, sip, 0, true);
			if (!*(__sum16 *)sum)
				*(__sum16 *)sum = CSUM_MANGLED_0;
			break;
		case IPPROTO_UDPLITE:
			if (!pskb_may_pull_iprhdr_ext(skb, sizeof(struct udphdr))) {
				LOG_ERROR("UDPLITE header offset exceed");
				return -EFAULT;
			}
			sum = skb_transport_header(skb) + CAPL + offsetof(struct udphdr, check);
			inet_proto_csum_replace4((__sum16 *)sum, skb, sip, 0, true);
			break;
		case IPPROTO_TCP:
			if (!pskb_may_pull_iprhdr_ext(skb, sizeof(struct tcphdr))) {
				LOG_ERROR("TCP header offset exceed");
				return -EFAULT;
			}
			sum = skb_transport_header(skb) + CAPL + offsetof(struct tcphdr, check);
			inet_proto_csum_replace4((__sum16 *)sum, skb, sip, 0, true);
			break;
		case IPPROTO_DCCP:
			if (!pskb_may_pull_iprhdr_ext(skb, sizeof(struct tcphdr))) {
				LOG_ERROR("DCCP header offset exceed");
				return -EFAULT;
			}
			sum = skb_transport_header(skb) + CAPL + offsetof(struct dccp_hdr, dccph_checksum);
			inet_proto_csum_replace4((__sum16 *)sum, skb, sip, 0, true);
			break;
	}
	LOG_INFO("csum: csum_offset checksum 0x%x", *(__be16 *)((skb->csum_start+skb->head)+skb->csum_offset));

	LOG_DEBUG("%pI4 -> %pI4: go to proxy", &ip_hdr(skb)->saddr,
			&ip_hdr(skb)->daddr);
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

	/* skb is defraged */
	if (!pskb_may_pull_iprhdr(skb))
		return false;

	udph = udp_hdr(skb);
	if (!is_server_port(udph->source))
		return false;

	iprh = ipr_hdr(skb);
	if (!is_ipr_sc(iprh))
		return false;

	LOG_DEBUG("%pI4 -> %pI4: yes", &ip_hdr(skb)->saddr, &ip_hdr(skb)->daddr);
	return true;
}

static unsigned int do_client_decap(struct sk_buff *skb)
{
	int nhl;
	struct iphdr *iph, *niph;
	struct iprhdr *iprh;
	struct udphdr *udph;
	struct tcphdr *tcph;
	struct dccp_hdr *dccph;
	__be32 server_ip;
    __be32 dip;

	nhl = skb_network_header_len(skb);

	iph = ip_hdr(skb);
	server_ip = iph->saddr;
	LOG_DEBUG("%pI4 -> %pI4: decap", &iph->saddr, &iph->daddr);
	iprh = ipr_hdr(skb);
    dip = iprh->ip;
	if (iprh->mask) {
		unsigned char mask = ntohs(iprh->mask);
        __be32 network = get_network(dip, mask);
        /*
		route_table_add(route_table, get_network(dip, mask),
				ntohs(iprh->mask));
                */
		LOG_DEBUG("add route %pI4/%u", &network, mask);
	}

	iph->protocol = iprh->protocol;
	iph->saddr = dip;
	iph->tot_len = htons(ntohs(iph->tot_len) - CAPL);
	ip_send_check(iph);

	niph = (struct iphdr *)__skb_pull(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	__skb_pull(skb, nhl);
	demasq_data(skb, get_password());
	__skb_push(skb, nhl);

	LOG_DEBUG("protocol %u ip_summed %u", niph->protocol, skb->ip_summed);
	LOG_DEBUG("csum: csum 0x%x", skb->csum);
	switch (niph->protocol) {
		case IPPROTO_UDP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct udphdr))) {
				LOG_ERROR("%pI4 -> %pI4: UDP too short",
						&niph->saddr,
						&niph->daddr);
				return -EINVAL;
			}
			udph = udp_hdr(skb);
			if (!udph->check)
				break;
			csum_replace4(&udph->check, server_ip, dip);
			if (!udph->check)
				udph->check = CSUM_MANGLED_0;
			skb->ip_summed = CHECKSUM_NONE;
			break;
		case IPPROTO_UDPLITE:
			if (!pskb_may_pull(skb, nhl + sizeof(struct udphdr))) {
				LOG_ERROR("%pI4 -> %pI4: UDPLITE too short",
						&niph->saddr,
						&niph->daddr);
				return -EINVAL;
			}
			udph = udp_hdr(skb);
			csum_replace4(&udph->check, server_ip, dip);
			skb->ip_summed = CHECKSUM_NONE;
			break;
		case IPPROTO_TCP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct tcphdr))) {
				LOG_ERROR("%pI4 -> %pI4: TCP too short",
						&niph->saddr,
						&niph->daddr);
				return -EINVAL;
			}
			tcph = tcp_hdr(skb);
			csum_replace4(&tcph->check, 0, in_aton("10.0.2.15"));
			skb->ip_summed = CHECKSUM_NONE;
			break;
		case IPPROTO_DCCP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct dccp_hdr))) {
				LOG_ERROR("%pI4 -> %pI4: DCCP too short",
						&niph->saddr,
						&niph->daddr);
				return -EINVAL;
			}
			dccph = dccp_hdr(skb);
			csum_replace4(&dccph->dccph_checksum, server_ip, dip);
			skb->ip_summed = CHECKSUM_NONE;
			break;
	}

	LOG_DEBUG("%pI4 -> %pI4: received", &niph->saddr, &niph->daddr);
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
		.hooknum = NF_INET_LOCAL_OUT, /* before routing */
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = client_encap,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD, /* before routing, need iptables defrag, used by router */
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = client_decap,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN, /* after defrag */
		.priority = NF_IP_PRI_FIRST,
	},
	{
		.hook = client_decap,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD, /* need iptables defrag, used by router */
		.priority = NF_IP_PRI_FIRST,
	},
};

#include "module.h"
