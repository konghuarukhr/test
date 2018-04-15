#include "common.h"
#include "kgenl.h"

#define ROUTE_EXPIRE 3600

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

static inline bool is_client_port(__be16 port)
{
	return port == _client_port;
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

	/* Do we need this? */
	if (is_server_ip(dip))
		return false;

	if (is_private_ip(dip))
		return false;

	if (is_noproxy_ip(dip))
		return false;

	LOG_DEBUG("%pI4 -> %pI4: yes", &sip, &dip);
	return true;
}

static int do_client_encap(struct sk_buff *skb)
{
	int err;
	int nhl;
	__be32 sip;
	__be32 dip;
	__u16 nlen;
	struct iphdr *iph, *niph;
	struct udphdr *udph;
	struct iprhdr *iprh;
	__be32 pip;
	volatile long begin, end;

	begin = jiffies;

	pip = get_server_ip();
	nhl = skb_network_header_len(skb);

	iph = ip_hdr(skb);
	sip = iph->saddr;
	dip = iph->daddr;
	nlen = ntohs(iph->tot_len) + CAPL;
	LOG_DEBUG("%pI4 -> %pI4: encap", &sip, &dip);
	if (unlikely(nlen < CAPL)) {
		LOG_ERROR("%pI4 -> %pI4: packet too large", &sip, &dip);
		return -EMSGSIZE;
	}

	err = skb_cow(skb, CAPL);
	if (err) {
		LOG_ERROR("%pI4 -> %pI4: failed to do skb_cow: %d", &sip, &dip,
				err);
		return err;
	}

	iph = ip_hdr(skb);
	niph = (struct iphdr *)__skb_push(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	iprh = ipr_hdr(skb);
	set_ipr_cs(iprh, niph->protocol, my_get_user(), dip);

	udph = udp_hdr(skb);
	udph->source = get_client_port();
	udph->dest = get_server_port();
	udph->len = htons(nlen - nhl);
	udph->check = 0;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	niph->protocol = IPPROTO_UDP;
	niph->daddr = pip;
	niph->tot_len = htons(nlen);
	ip_send_check(niph);

	__skb_pull(skb, nhl + CAPL);
	masq_data(skb, get_password());
	__skb_push(skb, nhl + CAPL);

	end = jiffies;
	LOG_DEBUG("%pI4 -> %pI4: go to proxy: %pI4, cost %ld", &sip, &dip, &pip, end - begin);
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

	LOG_DEBUG("%pI4 <- %pI4: yes", &ip_hdr(skb)->daddr,
			&ip_hdr(skb)->saddr);
	return true;
}

static unsigned int do_client_decap(struct sk_buff *skb)
{
	int err;
	int nhl;
	__be32 sip;
	__be32 dip;
	__be32 rip;
	struct iphdr *iph, *niph;
	struct udphdr *udph;
	struct iprhdr *iprh;
	struct tcphdr *tcph;
	struct dccp_hdr *dccph;
	__u16 udplitecov;
	__wsum csum;
	volatile long begin, end;

	begin = jiffies;
	nhl = skb_network_header_len(skb);

	__skb_pull(skb, nhl + CAPL);
	demasq_data(skb, get_password());
	__skb_push(skb, nhl + CAPL);

	iph = ip_hdr(skb);
	iprh = ipr_hdr(skb);
	sip = iph->saddr;
	dip = iph->daddr;
	rip = iprh->ip;
	LOG_DEBUG("%pI4 <- %pI4: decap", &dip, &sip);

	if (iprh->mask) {
		__u8 mask = ntohs(iprh->mask);
		LOG_DEBUG("%pI4 <- %pI4: add route %pI4/%u", &dip, &sip, &rip,
				mask);
		err = route_table_add_expire(route_table, rip, mask,
				ROUTE_EXPIRE);
		if (err)
			LOG_WARN("%pI4 <- %pI4: failed to add route %pI4/%u",
					&dip, &sip, &rip, mask);
	}

	iph->protocol = iprh->protocol;
	iph->saddr = rip;
	iph->tot_len = htons(ntohs(iph->tot_len) - CAPL);
	ip_send_check(iph);

	//skb->ip_summed = CHECKSUM_COMPLETE;

	niph = (struct iphdr *)__skb_pull(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);
#if 1
	switch (niph->protocol) {
		case IPPROTO_UDP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct udphdr))) {
				LOG_ERROR("%pI4 <- %pI4: UDP too short",
						&dip, &sip);
				return -ETOOSMALL;
			}
			udph = udp_hdr(skb);
			/*
			LOG_DEBUG("XXZ 0x%04x", udph->check);
			LOG_DEBUG("XXY %pI4 %pI4 %u", &vip, &rip, udph->len);
			LOG_DEBUG("XXY %pI4 %pI4 %u", &vip, &rip, ntohs(udph->len));
			LOG_DEBUG("XXX %u %u", skb->csum_start, skb->csum_offset);
			*/
			udph->check = ~csum_tcpudp_magic(rip, dip, ntohs(udph->len),
					IPPROTO_UDP, 0);
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum_start = skb_transport_header(skb) - skb->head;
			skb->csum_offset = offsetof(struct udphdr, check);
			//LOG_DEBUG("XXY 0x%04x", udph->check);
			//LOG_DEBUG("XXX %u %u", skb->csum_start, skb->csum_offset);
			break;
		case IPPROTO_UDPLITE:
			if (!pskb_may_pull(skb, nhl + sizeof(struct udphdr))) {
				LOG_ERROR("%pI4 <- %pI4: UDPLITE too short",
						&dip, &sip);
				return -ETOOSMALL;
			}
			udph = udp_hdr(skb);
			udplitecov = ntohs(udph->len);
			if (!udplitecov)
				udplitecov = skb->len -
					skb_transport_offset(skb);
			else if (udplitecov > skb->len -
					skb_transport_offset(skb)) {
				LOG_ERROR("%pI4 <- %pI4: UDPLITE coverage error",
						&dip, &sip);
				return -EFAULT;
			}
			csum = skb_checksum(skb, skb_transport_offset(skb),
					udplitecov, 0);
			udph->check = csum_tcpudp_magic(rip, dip, udph->len,
					IPPROTO_UDP, csum);
			if (!udph->check)
				udph->check = CSUM_MANGLED_0;
			skb->ip_summed = CHECKSUM_NONE;
			break;
		case IPPROTO_TCP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct tcphdr))) {
				LOG_ERROR("%pI4 <- %pI4: TCP too short",
						&dip, &sip);
				return -ETOOSMALL;
			}
			tcph = tcp_hdr(skb);
			tcph->check = ~csum_tcpudp_magic(rip, dip, skb->len -
					skb_transport_offset(skb), IPPROTO_TCP,
					0);
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum_start = skb_transport_header(skb) - skb->head;
			skb->csum_offset = offsetof(struct tcphdr, check);
			break;
		case IPPROTO_DCCP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct dccp_hdr))) {
				LOG_ERROR("%pI4 <- %pI4: DCCP too short",
						&dip, &sip);
				return -ETOOSMALL;
			}
			dccph = dccp_hdr(skb);
			csum_replace4(&dccph->dccph_checksum, 0, rip);
			skb->ip_summed = CHECKSUM_NONE;
			break;
	}
#endif

	end = jiffies;
	LOG_DEBUG("%pI4 <- %pI4: received: %pI4, %ld", &dip, &sip, &rip, end - begin);
	return 0;
}

static unsigned int client_encap(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	int err;

	if (!need_client_encap(skb))
		return NF_ACCEPT;

	err = do_client_encap(skb);
	if (err) {
		LOG_ERROR("failed to do client encap, drop packet: %d", err);
		return NF_DROP;
	}

	return NF_ACCEPT;
}

static unsigned int client_decap(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	int err;

	if (!need_client_decap(skb))
		return NF_ACCEPT;

	err = do_client_decap(skb);
	if (err) {
		LOG_ERROR("failed to do client decap, drop packet: %d", err);
		return NF_DROP;
	}

	return NF_ACCEPT;
}

static const struct nf_hook_ops iproxy_nf_ops[] = {
	{
		.hook = client_encap,
		.pf = NFPROTO_IPV4,
		//.hooknum = NF_INET_LOCAL_OUT, /* before frag, before routing */
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
//	{
//		.hook = client_encap,
//		.pf = NFPROTO_IPV4,
//		.hooknum = NF_INET_FORWARD,
//		.priority = NF_IP_PRI_LAST,
//		//.priority = NF_IP_PRI_CONNTRACK_DEFRAG + 1,
//	},
	{
		.hook = client_decap,
		.pf = NFPROTO_IPV4,
		//.hooknum = NF_INET_LOCAL_IN, /* after defrag */
		.hooknum = NF_INET_PRE_ROUTING,
		//.priority = NF_IP_PRI_LAST,
		.priority = NF_IP_PRI_CONNTRACK_DEFRAG + 1,
	},
//	{
//		.hook = client_decap,
//		.pf = NFPROTO_IPV4,
//		.hooknum = NF_INET_FORWARD, /* used in forwarding mode, NEED iptables defrag */
//		//.priority = NF_IP_PRI_CONNTRACK_DEFRAG + 1,
//		.priority = NF_IP_PRI_FIRST,
//	},
};


#include "module.h"
