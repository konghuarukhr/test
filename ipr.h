#ifndef _IPR_H_
#define _IPR_H_

struct iprhdr {
	__u8 type;
	__u8 protocol;
	__be16 user;
	__u32 ip;
};

#define CAPL (sizeof(struct udphdr) + sizeof(struct iprhdr))

enum {
	IPR_C_S, /* Client -> Server */
	IPR_S_C, /* Server -> Client */
};

static inline bool is_ipr_cs(const struct iprhdr *iprh)
{
	return iprh->type == IPR_C_S;
}

static inline bool is_ipr_sc(const struct iprhdr *iprh)
{
	return iprh->type == IPR_S_C;
}

static inline int pskb_may_pull_iprhdr(struct sk_buff *skb)
{
	return pskb_may_pull(skb, skb_network_header_len(skb) + CAPL);
}

static inline struct iprhdr *ipr_hdr(const struct sk_buff *skb)
{
	return (struct iprhdr *)(skb_transport_header(skb) +
			sizeof(struct udphdr));
}

#endif
