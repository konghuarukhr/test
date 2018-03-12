#include "masq.h"
#include "common.h"

#if 0
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#ifndef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE 1000000000
#endif

#ifndef skb_frag_foreach_page
static inline bool skb_frag_must_loop(struct page *p)                            
{                                                                                
#if defined(CONFIG_HIGHMEM)                                                      
	if (PageHighMem(p))                                                      
		return true;                                                     
#endif                                                                           
	return false;                                                            
}
#define skb_frag_foreach_page(f, f_off, f_len, p, p_off, p_len, copied) \
	for (p = skb_frag_page(f) + ((f_off) >> PAGE_SHIFT),        \
			p_off = (f_off) & (PAGE_SIZE - 1),             \
			p_len = skb_frag_must_loop(p) ?                \
			min_t(u32, f_len, PAGE_SIZE - p_off) : f_len,      \
			copied = 0;                        \
			copied < f_len;                        \
			copied += p_len, p++, p_off = 0,               \
			p_len = min_t(u32, f_len - copied, PAGE_SIZE))     \

#endif
#endif

/**
 * masq_bytes - masq data on each byte
 * @data: data to be masqed
 * @len: len of data
 * @passwd: password
 *
 * You can modify it to custom your own masq method.
 * Masq should be based on each byte, so you can demasq it without any position
 * info later.
 */
static inline void masq_bytes(void *data, int len, unsigned long passwd)
{
	return;
/*
	int i;
	__u8 *b;

	b = (__u8 *)data;
	for (i = 0; i < len; i++) {
		*b = ~*b + passwd;
		b++;
	}
	*/
}

/**
 * demasq_bytes - demasq data on each byte
 * @data: data to be demasqed
 * @len: len of data
 * @passwd: password
 *
 * Corresponding to masq_bytes().
 * Masq is based on each byte, so you can demasq it without any position info
 * now.
 */
static inline void demasq_bytes(void *data, int len, unsigned long passwd)
{
	return;
/*
	int i;
	__u8 *b;

	b = (__u8 *)data;
	for (i = 0; i < len; i++) {
		*b = ~*b - passwd;
		b++;
	}
	*/
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

static void process_data(struct sk_buff *skb,
		void (*do_process)(void *, int, unsigned long),
		unsigned long passwd)
{
	int i;
	int start;
	
	start = skb_headlen(skb);
	do_process(skb->data, start, passwd);

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *f = &skb_shinfo(skb)->frags[i];
		u32 f_len = skb_frag_size(f);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
		{
			void *vaddr = kmap_atomic(skb_frag_page(f));
			do_process(vaddr + f->page_offset, f_len, passwd);
			kunmap_atomic(vaddr);
		}
#else
		{
			u32 p_off, p_len, copied;
			struct page *p;
			skb_frag_foreach_page(f,
					f->page_offset,
					f_len, p, p_off, p_len, copied) {
				void *vaddr = kmap_atomic(p);
				do_process(vaddr + p_off, p_len, passwd);
				kunmap_atomic(vaddr);
			}
		}
#endif
	}
	{
		struct sk_buff *frag_iter;
		skb_walk_frags(skb, frag_iter) {
			process_data(frag_iter, do_process, passwd);
		}
	}
}

void masq_data(struct sk_buff *skb, unsigned long passwd)
{
	process_data(skb, masq_bytes, passwd);
}

void demasq_data(struct sk_buff *skb, unsigned long passwd)
{
	process_data(skb, demasq_bytes, passwd);
}
