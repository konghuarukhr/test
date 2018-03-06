#include "common.h"
#include "kgenl.h"

#define VIP_EXPIRE 300

static struct xlate_table *xlate_table = NULL;

static char *server_ip = NULL;
module_param(server_ip, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(server_ip, "local IP for receiving packets from client");
static __be32 _server_ip = 0;

static unsigned short server_port = 0;
module_param(server_port, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(server_port, "UDP port used and reserved");
static __be16 _server_port = 0;

static char *vip_start = NULL;
module_param(vip_start, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(vip_start, "virtual and unreachable client IP range from");
static __u32 _vip_start = 0;
static __u32 _vip_end = 0;

static unsigned int vip_number = 0;
module_param(vip_number, uint, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(vip_number, "virtual and unreachable client IP total number");

static char *dns_ip = NULL;
module_param(dns_ip, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(dns_ip, "DNS IP used to replace private IP or noproxy IP");
static __be32 _dns_ip = 0;

/**
 * TODO: supports multi proxies
 */
static inline __be32 get_server_ip(void)
{
	return _server_ip;
}

static inline bool is_server_ip(__be32 ip)
{
	return ip == _server_ip;
}

static inline __be16 get_server_port(void)
{
	return _server_port;
}

static inline bool is_server_port(__be16 port)
{
	return port == _server_port;
}

static inline __u32 get_vip_start(void)
{
	return _vip_start;
}

static inline bool is_in_vip_range(__u32 ip)
{
	return ip >= _vip_start && ip < _vip_end;
}

static inline unsigned int get_vip_number(void)
{
	return vip_number;
}

static inline __be32 get_dns_ip(void)
{
	return _dns_ip;
}

static inline unsigned char get_passwd(__be16 user)
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
	_vip_end = _vip_start + vip_number;

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

static int custom_init(void)
{
	int err;

	err = params_init();
	if (err) {
		LOG_ERROR("failed to init input params: %d", err);
		goto params_init_err;
	}

	route_table = route_table_init();
	if (!route_table) {
		err = -ENOMEM;
		LOG_ERROR("failed to init route table");
		goto route_table_init_err;
	}

	xlate_table = xlate_table_init(get_vip_start(), get_vip_number(),
			VIP_EXPIRE);
	if (!xlate_table) {
		err = -ENOMEM;
		LOG_ERROR("failed to init xlate table");
		goto xlate_table_init_err;
	}

	return 0;

xlate_table_init_err:
	route_table_uninit(route_table);

route_table_init_err:
	params_uninit();

params_init_err:
	return err;
}

static void custom_uninit(void)
{
	xlate_table_uninit(xlate_table);
	route_table_uninit(route_table);
	params_uninit();
}

static inline bool is_noproxy_ip(__be32 ip)
{
	return route_table_get_mask(route_table, ip);
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

	if (!pskb_may_pull_iprhdr(skb))
		return false;

	udph = udp_hdr(skb);
	if (!is_server_port(udph->dest))
		return false;

	iprh = ipr_hdr(skb);
	if (!is_ipr_cs(iprh))
		return false;

	LOG_DEBUG("%pI4 -> %pI4: yes", &ip_hdr(skb)->saddr, &ip_hdr(skb)->daddr);
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
	__be32 dip;
	__be16 user;
	struct tcphdr *tcph;
	struct dccp_hdr *dccph;

	nhl = skb_network_header_len(skb);

	iph = ip_hdr(skb);
	udph = udp_hdr(skb);
	iprh = ipr_hdr(skb);

	dip = iprh->ip;
	user = iprh->user;

	LOG_DEBUG("%pI4:%u:%u -> %pI4: decap", &iph->saddr,
			ntohs(udph->source), user, &iph->daddr);
	err = xlate_table_lookup_vip(xlate_table, iph->saddr, udph->source,
			user, &xvip);
	if (err) {
		LOG_ERROR("failed to lookup xlate vip by ip %p4I port %u user %u: %d",
				&iph->saddr, ntohs(udph->source), user, err);
		return err;
	}
	LOG_DEBUG("found xlate vip %pI4 by ip %pI4 port %u user %u", &xvip,
			&iph->saddr, ntohs(udph->source), user);

	__skb_pull(skb, nhl + CAPL);
	LOG_DEBUG("before masq: 0x%02x", *(__u8 *)skb->data);
	demasq_data(skb, get_passwd(user));
	LOG_DEBUG("after masq: 0x%02x", *(__u8 *)skb->data);
	__skb_push(skb, nhl + CAPL);

	iph->protocol = iprh->protocol;
	iph->saddr = xvip;
	iph->daddr = dip;
	LOG_DEBUG("dip %pI4 %u", &dip, iph->protocol);
	if (iph->protocol == IPPROTO_UDP &&
			pskb_may_pull_iprhdr_ext(skb, sizeof(struct udphdr)) &&
			is_dns_port((struct udphdr *)(skb_transport_header(skb) + CAPL))) {
		LOG_DEBUG("dip %pI4 %d", &dip, is_private_ip(dip));
		iph = ip_hdr(skb);
		if (is_private_ip(dip) || is_noproxy_ip(dip)) {
			__be32 dnsip = get_dns_ip();
			iph->daddr = dnsip;
			LOG_DEBUG("change dest ip to %pI4", &dnsip);
		}
	}
	iph->tot_len = htons(ntohs(iph->tot_len) - CAPL);
	ip_send_check(iph);

	niph = (struct iphdr *)__skb_pull(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	LOG_DEBUG("protocol %u ip_summed %u", niph->protocol, skb->ip_summed);
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
			csum_replace4(&udph->check, 0, xvip);
			if (iph->daddr != dip) {
				LOG_DEBUG("%pI4 -> %pI4", &dip, &niph->daddr);
				csum_replace4(&udph->check, dip, niph->daddr);
			}
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
			csum_replace4(&udph->check, 0, xvip);
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
			csum_replace4(&tcph->check, 0, xvip);
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
			csum_replace4(&dccph->dccph_checksum, 0, xvip);
			skb->ip_summed = CHECKSUM_NONE;
			break;
	}

	LOG_DEBUG("%pI4 -> %pI4: go to server", &niph->saddr, &niph->daddr);
	return 0;
}

static bool need_server_encap(struct sk_buff *skb)
{
	struct iphdr *iph;

	iph = ip_hdr(skb);
	if (!is_in_vip_range(ntohl(iph->daddr)))
		return false;

	LOG_DEBUG("%pI4 -> %pI4: yes", &iph->saddr, &iph->daddr);
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
	LOG_DEBUG("%pI4 -> %pI4: encap", &iph->saddr, &iph->daddr);
	err = xlate_table_find_ipport(xlate_table, iph->daddr, &xip, &xport,
			&xuser);
	if (err) {
		LOG_ERROR("failed to find xlate ipport by vip %pI4: %d",
				&iph->daddr, err);
		return err;
	}
	LOG_DEBUG("found xlate ip %pI4 port %u user %u by vip %pI4", &xip,
			ntohs(xport), xuser, &iph->daddr);

	err = skb_cow(skb, CAPL);
	if (err) {
		LOG_ERROR("failed to do skb_cow on packet vip %pI4: %d",
				&iph->daddr, err);
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
	iprh->mask = htons(route_table_get_mask(route_table, niph->saddr));
	iprh->ip = niph->saddr;

	udph = udp_hdr(skb);
	udph->source = get_server_port();
	udph->dest = xport;
	udph->len = htons(ntohs(niph->tot_len) + CAPL - nhl);
	udph->check = 0;

	niph->protocol = IPPROTO_UDP;
	niph->saddr = get_server_ip();
	niph->daddr = xip;
	niph->tot_len = htons(ntohs(niph->tot_len) + CAPL);
	ip_send_check(niph);

	LOG_DEBUG("%pI4 -> %pI4:%u: go to client", &niph->saddr, &niph->daddr,
			ntohs(udph->dest));
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


#include "module.h"
