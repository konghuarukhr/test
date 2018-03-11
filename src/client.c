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

static char *dns_ip = NULL;
module_param(dns_ip, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(dns_ip, "DNS IP used to replace private DNS IP or noproxy DNS IP");
static __be32 _dns_ip = 0;

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

static inline __be32 get_dns_ip(void)
{
	return _dns_ip;
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
	if (server_ip)
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

	if (dns_ip)
		_dns_ip = in_aton(dns_ip);
	if (!_dns_ip && !is_dns_no_special()) {
		LOG_ERROR("dns_ip param error");
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

/**
 * dirty local DNS IP
 * we assume only one IP will be used in a period of time
 * we don't use lock to protect it to avoid overhead
 * if we get the wrong local_dns_ip, it will lead to packet drop, and retransmit
 * this packet
 */
static __be32 local_dns_ip = 0;

static inline void set_local_dns_ip(__be32 ip)
{
	if (local_dns_ip != ip)
		local_dns_ip = ip;
}

static inline __be32 get_local_dns_ip(void)
{
	return local_dns_ip;
}

static bool need_client_encap(struct sk_buff *skb)
{
	struct iphdr *iph;
	__be32 sip;
	__be32 dip;

	iph = ip_hdr(skb);
	sip = iph->saddr;
	dip = iph->daddr;

	if (is_server_ip(dip))
		return false;

	if (!is_dns_no_special() && iph->protocol == IPPROTO_UDP &&
			pskb_may_pull(skb, skb_network_header_len(skb) + CAPL +
				sizeof(struct udphdr)) &&
			udp_hdr(skb)->dest == DNS_PORT) {
		if (is_dns_all()) {
			LOG_DEBUG("%pI4 -> %pI4: yes, dns all", &sip, &dip);
			return true;
		}

		if (is_dns_public() && !is_private_ip(dip)) {
			LOG_DEBUG("%pI4 -> %pI4: yes, dns public", &sip, &dip);
			return true;
		}

		return false;
	}

	if (is_private_ip(dip))
		return false;

	if (is_route_proxy() && is_noproxy_ip(dip))
		return false;

	LOG_DEBUG("%pI4 -> %pI4: yes", &sip, &dip);
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
	__be32 dip;
	bool rewrite_dns;
	__sum16 *sum;

	nhl = skb_network_header_len(skb);

	iph = ip_hdr(skb);
	sip = iph->saddr;
	dip = iph->daddr;
	LOG_DEBUG("%pI4 -> %pI4: encap", &sip, &dip);

	err = skb_cow(skb, CAPL);
	if (err) {
		LOG_ERROR("%pI4 -> %pI4: failed to do skb_cow: %d", &sip, &dip,
				err);
		return err;
	}

	iph = ip_hdr(skb);
	if (!is_dns_no_special() && iph->protocol == IPPROTO_UDP &&
			*(__be16 *)(skb_transport_header(skb) + CAPL +
				offsetof(struct udphdr, dest)) == DNS_PORT) {
		rewrite_dns = true;
		LOG_DEBUG("%pI4 -> %pI4: rewrite DNS IP", &sip, &dip);
	} else
		rewrite_dns = false;

	iph = ip_hdr(skb);
	niph = (struct iphdr *)__skb_push(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	iprh = ipr_hdr(skb);
	set_ipr_cs(iprh);
	iprh->protocol = niph->protocol;
	iprh->user = my_get_user();
	if (rewrite_dns) {
		set_local_dns_ip(dip);
		iprh->ip = get_dns_ip();
	} else
		iprh->ip = dip;

	udph = udp_hdr(skb);
	udph->source = get_client_port();
	udph->dest = get_server_port();
	udph->len = htons(ntohs(niph->tot_len) - nhl + CAPL);
	udph->check = 0;

	niph->protocol = IPPROTO_UDP;
	niph->daddr = get_server_ip();
	niph->tot_len = htons(ntohs(niph->tot_len) + CAPL);
	ip_send_check(niph);

	if (skb->ip_summed == 3)
		LOG_INFO("csum: csum_offset checksum 0x%x", *(__be16 *)((skb->csum_start+skb->head)+skb->csum_offset));

	LOG_DEBUG("protocol %u ip_summed %u csum 0x%08x", iprh->protocol,
			skb->ip_summed, skb->csum);
	switch (iprh->protocol) {
		case IPPROTO_UDP:
			if (!pskb_may_pull_iprhdr_ext(skb,
						sizeof(struct udphdr))) {
				LOG_ERROR("%pI4 -> %pI4: UDP too short", &sip,
						&dip);
				return -EFAULT;
			}
			sum = (__sum16 *)(skb_transport_header(skb) + CAPL +
				offsetof(struct udphdr, check));
			if (!*sum && skb->ip_summed != CHECKSUM_PARTIAL)
				break;
			inet_proto_csum_replace4(sum, skb, sip, 0, true);
			if (rewrite_dns)
				inet_proto_csum_replace4(sum, skb, dip,
						get_dns_ip(), true);
			if (!*sum)
				*sum = CSUM_MANGLED_0;
			break;
		case IPPROTO_UDPLITE:
			if (!pskb_may_pull_iprhdr_ext(skb,
						sizeof(struct udphdr))) {
				LOG_ERROR("%pI4 -> %pI4: UDPLITE too short",
						&sip, &dip);
				return -EFAULT;
			}
			sum = (__sum16 *)(skb_transport_header(skb) + CAPL +
				offsetof(struct udphdr, check));
			inet_proto_csum_replace4(sum, skb, sip, 0, true);
			break;
		case IPPROTO_TCP:
			if (!pskb_may_pull_iprhdr_ext(skb,
						sizeof(struct tcphdr))) {
				LOG_ERROR("%pI4 -> %pI4: TCP too short", &sip,
						&dip);
				return -EFAULT;
			}
			sum = (__sum16 *)(skb_transport_header(skb) + CAPL +
				offsetof(struct tcphdr, check));
			inet_proto_csum_replace4(sum, skb, sip, 0, true);
			break;
		case IPPROTO_DCCP:
			if (!pskb_may_pull_iprhdr_ext(skb,
						sizeof(struct tcphdr))) {
				LOG_ERROR("%pI4 -> %pI4: DCCP too short", &sip,
						&dip);
				return -EFAULT;
			}
			sum = (__sum16 *)(skb_transport_header(skb) + CAPL +
				offsetof(struct dccp_hdr, dccph_checksum));
			inet_proto_csum_replace4(sum, skb, sip, 0, true);
			break;
	}
	if (skb->ip_summed == 3)
		LOG_INFO("csum: csum_offset checksum 0x%x", *(__be16 *)((skb->csum_start+skb->head)+skb->csum_offset));

	__skb_pull(skb, nhl + CAPL);
	masq_data(skb, get_password());
	__skb_push(skb, nhl + CAPL);

	LOG_DEBUG("%pI4 -> %pI4: go to proxy", &sip, &dip);
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

	LOG_DEBUG("%pI4 <- %pI4: yes", &ip_hdr(skb)->daddr, &ip_hdr(skb)->saddr);
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
	__be32 sip;
	__be32 dip;
	__be32 pip;
	bool rewrite_dns;
	__be32 dns_ip;

	dns_ip = get_local_dns_ip();

	nhl = skb_network_header_len(skb);

	__skb_pull(skb, nhl + CAPL);
	demasq_data(skb, get_password());
	__skb_push(skb, nhl + CAPL);

	iph = ip_hdr(skb);
	sip = iph->saddr;
	dip = iph->daddr;
	LOG_DEBUG("%pI4 <- %pI4: decap", &dip, &sip);

	if (!is_dns_no_special() && iph->protocol == IPPROTO_UDP &&
			pskb_may_pull(skb, nhl + CAPL + sizeof(struct udphdr)) &&
			*(__be16 *)(skb_transport_header(skb) + CAPL +
				offsetof(struct udphdr, dest)) == DNS_PORT) {
		rewrite_dns = true;
		LOG_DEBUG("%pI4 <- %pI4: rewrite DNS IP", &dip, &sip);
	} else
		rewrite_dns = false;

	iph = ip_hdr(skb);
	iprh = ipr_hdr(skb);
	pip = iprh->ip;
	if (iprh->mask) {
		unsigned char mask = ntohs(iprh->mask);
		__be32 network = get_network(pip, mask);
		LOG_DEBUG("%pI4 <- %pI4: add route %pI4/%u", &dip, &sip,
				&network, mask);
		//route_table_add(route_table, network, mask);
	}
	iph->protocol = iprh->protocol;
	iph->saddr = rewrite_dns ? dns_ip : pip;
	iph->tot_len = htons(ntohs(iph->tot_len) - CAPL);
	ip_send_check(iph);

	niph = (struct iphdr *)__skb_pull(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	LOG_DEBUG("protocol %u ip_summed %u csum 0x%08x", niph->protocol,
			skb->ip_summed, skb->csum);
	switch (niph->protocol) {
		case IPPROTO_UDP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct udphdr))) {
				LOG_ERROR("%pI4 <- %pI4: UDP too short", &dip,
						&sip);
				return -EFAULT;
			}
			udph = udp_hdr(skb);
			if (!udph->check)
				break;
			csum_replace4(&udph->check, 0, dip);
			if (rewrite_dns)
				csum_replace4(&udph->check, pip, dns_ip);
			if (!udph->check)
				udph->check = CSUM_MANGLED_0;
			skb->ip_summed = CHECKSUM_NONE;
			break;
		case IPPROTO_UDPLITE:
			if (!pskb_may_pull(skb, nhl + sizeof(struct udphdr))) {
				LOG_ERROR("%pI4 <- %pI4: UDPLITE too short",
						&dip, &sip);
				return -EFAULT;
			}
			udph = udp_hdr(skb);
			csum_replace4(&udph->check, 0, dip);
			skb->ip_summed = CHECKSUM_NONE;
			break;
		case IPPROTO_TCP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct tcphdr))) {
				LOG_ERROR("%pI4 <- %pI4: TCP too short", &dip,
						&sip);
				return -EFAULT;
			}
			tcph = tcp_hdr(skb);
			csum_replace4(&tcph->check, 0, dip);
			skb->ip_summed = CHECKSUM_NONE;
			break;
		case IPPROTO_DCCP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct dccp_hdr))) {
				LOG_ERROR("%pI4 <- %pI4: DCCP too short", &dip,
						&sip);
				return -EFAULT;
			}
			dccph = dccp_hdr(skb);
			csum_replace4(&dccph->dccph_checksum, 0, dip);
			skb->ip_summed = CHECKSUM_NONE;
			break;
	}

	LOG_DEBUG("%pI4 <- %pI4: received", &dip, &sip);
	return 0;
}

static unsigned int client_encap(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	if (!need_client_encap(skb))
		return NF_ACCEPT;

	if (do_client_encap(skb)) {
		LOG_ERROR("drop packet in client encap");
		return NF_DROP;
	}

	return NF_ACCEPT;
}

static unsigned int client_decap(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	if (!need_client_decap(skb))
		return NF_ACCEPT;

	if (do_client_decap(skb)) {
		LOG_ERROR("drop packet in client decap");
		return NF_DROP;
	}

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
		.hooknum = NF_INET_FORWARD, /* before routing, NEED iptables defrag, used by router */
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
		.hooknum = NF_INET_FORWARD, /* NEED iptables defrag, used by router */
		.priority = NF_IP_PRI_FIRST,
	},
};


#include "module.h"
