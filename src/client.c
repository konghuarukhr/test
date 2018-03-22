#include "common.h"
#include "kgenl.h"

static struct route_table *route_table = NULL;

static char *server_ip = NULL;
module_param(server_ip, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(server_ip, "server IP");
static __be32 _server_ip = 0;

static unsigned short client_port = 0;
module_param(client_port, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(client_port, "client UDP port");
static __be16 _client_port = 0;

static unsigned short server_port = 0;
module_param(server_port, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(server_port, "server UDP port");
static __be16 _server_port = 0;

static unsigned short user = 0;
module_param(user, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(user, "user");
static __be16 _user = 0;

static unsigned long password = 0;
module_param(password, ulong, 0);
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

static inline __be16 get_client_port(void)
{
	return _client_port;
}

static inline bool is_server_port(__be16 port)
{
	return port == _server_port;
}

static inline __be16 get_server_port(void)
{
	return _server_port;
}

static inline __be16 my_get_user(void)
{
	return _user;
}

static inline unsigned long get_password(void)
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

	_client_port = htons(client_port);
	if (!_client_port) {
		LOG_ERROR("client_port param error");
		return -EINVAL;
	}

	_server_port = htons(server_port);
	if (!_server_port) {
		LOG_ERROR("server_port param error");
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
	return route_table_find(route_table, ip);
}

/**
 * dirty local DNS IP
 * we assume only one IP will be used in a period of time
 * we don't use lock to protect it to avoid overhead
 * if we get the wrong local_dns_ip, it will lead to packet drop, and retransmit
 * this packet
 * this should not be used in router where many clients used different DNS IP go
 * through the router
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
			pskb_may_pull(skb, skb_network_header_len(skb) +
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
			udp_hdr(skb)->dest == DNS_PORT) {
		rewrite_dns = true;
		LOG_DEBUG("%pI4 -> %pI4: rewrite DNS IP", &sip, &dip);
	} else
		rewrite_dns = false;

	niph = (struct iphdr *)__skb_push(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	iprh = ipr_hdr(skb);
	set_ipr_cs(iprh);
	iprh->protocol = niph->protocol;
	iprh->user = my_get_user();
	if (rewrite_dns) {
		/* dirty set, avaliable in a period, easy implement */
		set_local_dns_ip(dip);
		iprh->ip = get_dns_ip();
	} else
		iprh->ip = dip;

	udph = udp_hdr(skb);
	udph->source = get_client_port();
	udph->dest = get_server_port();
	udph->len = htons(ntohs(niph->tot_len) - nhl + CAPL);

	niph->protocol = IPPROTO_UDP;
	niph->daddr = get_server_ip();
	niph->tot_len = htons(ntohs(niph->tot_len) + CAPL);
	ip_send_check(niph);

	udph->check = 0;
	skb->ip_summed = CHECKSUM_NONE;

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
	__be32 sip;
	__be32 dip;
	__be32 pip;
	bool rewrite_dns;


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
				offsetof(struct udphdr, source)) == DNS_PORT) {
		rewrite_dns = true;
		LOG_DEBUG("%pI4 <- %pI4: rewrite DNS IP", &dip, &sip);
	} else
		rewrite_dns = false;

	iph = ip_hdr(skb);
	iprh = ipr_hdr(skb);
	pip = iprh->ip;
	if (iprh->mask) {
		unsigned char mask = ntohs(iprh->mask);
		LOG_DEBUG("%pI4 <- %pI4: add route %pI4/%u", &dip, &sip,
				&pip, mask);
		route_table_add(route_table, pip, mask);
	}
	iph->protocol = iprh->protocol;
	iph->saddr = rewrite_dns ? get_local_dns_ip() : pip;
	iph->tot_len = htons(ntohs(iph->tot_len) - CAPL);
	//ip_send_check(iph);

	//skb->ip_summed = CHECKSUM_COMPLETE;

	niph = (struct iphdr *)__skb_pull(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	LOG_DEBUG("%pI4 <- %pI4: received", &niph->daddr, &niph->saddr);
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
