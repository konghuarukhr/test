#include "common.h"

static char *server_ip = NULL;
module_param(server_ip, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(server_ip, "server ip");
static __be32 _server_ip = 0;

static unsigned short server_port = 0;
module_param(server_port, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(server_port, "server port (UDP)");
static __be16 _server_port = 0;

static unsigned short client_port = 0;
module_param(client_port, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(client_port, "source udp port");
static __be16 _client_port = 0;

static unsigned char passwd = 0;
module_param(passwd, byte, 0);
MODULE_PARM_DESC(passwd, "password");

static unsigned char dns_policy = 0;
module_param(dns_policy, byte, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(dns_policy, "0: proxy all; 1: not proxy private ip; 2: no special");
enum {
	DNS_ALL,
	DNS_PUBLIC,
	DNS_NO_SPECIAL,
};

static unsigned char route_policy = 0;
module_param(route_policy, byte, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(route_policy, "0: get route from server; 1: ignore route from server");
enum {
	ROUTE_SERVER,
	ROUTE_ALL,
}

static int param_init(void)
{
	_client_port = htons(client_port);
	if (server_ip == NULL) {
		return -EINVAL;
	}
	_server_ip = in_aton(server_ip);
	_server_port = htons(server_port);
	return 0;
}

static __be32 get_server_ip(void)
{
	return _server_ip;
}

static __be16 get_server_port(void)
{
	return _server_port;
}

static __be16 get_client_port(void)
{
	return _client_port;
}

static unsigned char get_passwd(void)
{
	return passwd;
}


static bool dport_is_dns_port(const struct udphdr *udph)
{
	return udph->dest == __constant_htons(53);
}

static bool is_dns_proto(const struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_UDP)
		if (pskb_network_may_pull(skb, sizeof(struct udphdr)))
			return dport_is_dns_port(udp_hdr(skb));
}

/**
 * https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
 */
static bool is_private_ip(__be32 addr)
{
	__be32 network;

	// 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8
	network = addr & 0xFF000000U;
	switch (network) {
		case 0x00000000U:
			return true;
		case 0x0A000000U:
			return true;
		case 0x7F000000U:
			return true;
	}

	// 100.64.0.0/10
	network = addr & 0xFFC00000U;
	if (network == 0x64400000U)
		return true;

	// 172.16.0.0/12
	network = addr & 0xFFF00000U;
	if (network == 0xAC100000U)
		return true;

	// 192.168.0.0/16
	network = addr & 0xFFFF0000U;
	if (network == 0xC0A80000U)
		return true;
}

static is_noproxy_dip(__be32 addr)
{
	return false;
}

static bool need_client_encap(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	if (is_server_ip(iph->daddr))
		return false;

	if (dns_policy != DNS_NO_SPECIAL && is_dns_proto(skb)) {
		if (dns_policy == DNS_ALL)
			return true;
		if (dns_policy == DNS_PUBLIC && !is_private_ip(iph->daddr))
			return true;
		return false;
	}

	if (is_private_ip(iph->daddr))
		return false;

	if (route_policy == ROUTE_SERVER && is_noproxy_dip(iph->daddr))
		return false;

	return true;
}

static int do_client_encap(struct sk_buff *skb)
{
	int err;

	int capl = sizeof(struct udphdr) + sizeof(struct iprhdr);
	if (err = skb_cow(skb, capl))
		return err;

	struct iphdr *iph = ip_hdr(skb);
	int nhl = skb_network_header_len(skb);

	__skb_pull(skb, nhl);
	masq_data(skb, get_passwd());

	void *niph = __skb_push(skb, nhl + capl);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	struct iprhdr *iprh = skb_transport_header(skb) + sizeof(struct udphdr);
	iprh->type = IPR_C_S;
	iprh->passwd = get_passwd();
	iprh->addr = niph->daddr;

	struct udphdr *udph = udp_hdr(skb);
	udph->source = get_client_port();
	udph->dest = get_server_port();
	udph->len = htons(ntohs(niph->tot_len) + capl - nhl);
	udph->check = 0;

	niph->daddr = get_server_ip();
	niph->tot_len = htons(ntohs(niph->tot_len) + capl);
	//niph->check = ;

	return 0;
}

/**
 * TODO: supports multi proxies
 */
static bool is_server_ip(__be16 ip)
{
	return ip == _server_ip;
}

static bool is_server_port(__be16 port)
{
	return port == _server_port;
}

static bool need_client_decap(struct sk_buff *skb) {
	struct iphdr *iph = ip_hdr(skb);
	if (!is_server_ip(iph->saddr))
		return false;

	if (iph->protocol != IPPROTO_UDP)
		return false;

	/* skb is defraged by nf_defrag_ipv4 */
	if (!pskb_network_may_pull(skb, sizeof(struct udphdr) +
				sizeof(struct iprhdr)))
		return false;

	struct udphdr *udph = udp_hdr(skb);
	if (!is_server_port(udph->source))
		return false;

	struct iprhdr *iprh = skb_transport_header(skb) + sizeof(struct udphdr);
	if (!is_server_to_client(iprh))
		return false;

	return true;
}

static unsigned int do_client_decap(struct sk_buff *skb) {
	int capl = sizeof(struct udphdr) + sizeof(struct iprhdr);

	struct iphdr *iph = ip_hdr(skb);
	struct iprhdr *iprh = skb_transport_header(skb) + sizeof(struct udphdr);
	iph->saddr = iprh->addr;
	iph->tot_len = htons(ntohs(iph->tot_len) - capl);
	//iph->check = ;

	int nhl = skb_network_header_len(skb);
	void *niph = __skb_pull(skb, capl);
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
		return NF_ACCEPT;

	return NF_ACCEPT;
}

static unsigned int client_decap(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	if (!need_client_decap(skb))
		return NF_ACCEPT;

	if (do_client_decap(skb))
		return NF_ACCEPT;

	return NF_ACCEPT;
}

static const struct nf_hook_ops iproxy_ops[] = {
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
}

#include "module.i"
