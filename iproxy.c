/**
 * masq_bytes - masq data on each byte
 * @data: data to be masqed
 * @len: len of data
 *
 * You can modify it to custom your own masq method.
 * Masq should be based on each byte, so you can demasq it without any position
 * info later.
 */
static inline void masq_bytes(void *data, int len)
{
	u8 *b = (u8 *)data;
	for (int i = 0; i < len; i++) {
		*b = ~*b;
	}
}

/**
 * demasq_bytes - demasq data on each byte
 * @data: data to be demasqed
 * @len: len of data
 *
 * Corresponding to masq_bytes().
 * Masq is based on each byte, so you can demasq it without any position info
 * now.
 */
static inline void demasq_bytes(void *data, int len)
{
	u8 *b = (u8 *)data;
	for (int i = 0; i < len; i++) {
		*b = ~*b;
	}
}

/**
 * recalc_csum - recalculate csum
 * @csum: original csum
 * @bytes: bytes of data
 *
 * Corresponding to masq_bytes().
 * Masq is based on each byte, so you can recalculate csum based on how many
 * bytes are changed
 */
static inline __be16 recalc_csum(__be16 csum, int bytes) {
	return ~csum;
}

static int process_data(struct sk_buff *skb, void (*do_process)(void *, int))
{
	int start = skb_headlen(skb);
	do_process(skb->data, start);
	for (int i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *f = &skb_shinfo(skb)->frags[i];
		u32 f_len = skb_frag_size(f);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,14)
		void *vaddr = kmap_atomic(skb_frag_page(f));
		do_process(vaddr + f->page_offset, f_len);
		kunmap_atomic(vaddr);
#else
		u32 p_off, p_len, copied;
		struct page *p;
		skb_frag_foreach_page(f,
				f->page_offset,
				f_len, p, p_off, p_len, copied) {
			void *vaddr = kmap_atomic(p);
			do_process(vaddr + p_off, p_len);
			kunmap_atomic(vaddr);
		}
#endif
	}
	struct sk_buff *frag_iter;
	skb_walk_frags(skb, frag_iter) {
		process_data(frag_iter, do_process);
	}
}

void masq_data(struct sk_buff *skb)
{
	process_data(skb, masq_bytes);
}

void demasq_data(struct sk_buff *skb)
{
	process_data(skb, demasq_bytes);
}


static inline void encap(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	if ()
}

/**
 * TODO: support multi proxies
 */
static bool is_proxy_ip(const iphdr *iph)
{
	return iph->saddr == PROXY_IP;
}

static bool is_proxy_port(const udphdr *udph)
{
	return udph->source == PROXY_PORT;
}

static bool ip_proxy(const sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	if (!is_proxy_ip(iph)) {
		return false;
	}

	if (iph->protocol != IPPROTO_UDP) {
		return false;
	}

	struct udphdr *udph = udp_hdr(skb);
	if (!is_proxy_port(udph)) {
		return false;
	}

	return true;
}

static inline void decap(struct sk_buff *skb)
{
	if (!is_proxy(skb)) {
		return;
	}

	__skb_pull(skb, skb_network_header_len(skb));
	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		return;

	struct udphdr *udph = udp_hdr(skb);
	struct prxhdr *prxh = proxy_hdr((void *)udph + sizeof(struct udphdr));
	void *p = skb_push(skb, iph->ihl * 4);
	iph->saddr = prxh->addr;
	memmove(iph + sizeof(struct prxhdr), iph, iph->ihl * 4);
	// TODO: csum
}

