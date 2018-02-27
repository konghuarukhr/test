#include "route.h"
#include "common.h"

#define ROUTE_BUCKET_BITS 10
#define ROUTE_BUCKET_NR 25 // mask: 8-32

struct route_bucket {
	DECLARE_HASHTABLE(head, ROUTE_BUCKET_BITS);
	int size;
	spinlock_t lock;
	__be32 mask;
};

struct route_entry {
	struct route_bucket *rb;
	__be32 network;
	struct timer_list timer;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct route_table {
	struct route_bucket buckets[ROUTE_BUCKET_NR];
};

struct route_table *route_table_init(void)
{
	int i;
	struct route_table *rt;
	
	rt = kzalloc(sizeof *rt, GFP_KERNEL);
	if (!rt) {
		LOG_ERROR("failed to alloc route table");
		return NULL;
	}

	for (i = 0; i < ARRAY_SIZE(rt->buckets); i++) {
		struct route_bucket *rb;

		rb = rt->buckets + i;
		hash_init(rb->head);
		rb->size = 0;
		spin_lock_init(&rb->lock);
		rb->mask = htonl(-(1 << i));
	}

	return rt;
}

static void route_entry_release(struct route_entry *re)
{
	del_timer(&re->timer);
	hash_del_rcu(&re->node);
	re->rb->size--;
	kfree_rcu(re, rcu);
}

void route_table_clear(struct route_table *rt)
{
	int i;

	for (i = 0; i < ROUTE_BUCKET_NR; i++) {
		struct route_bucket *rb;
		int bkt;
		struct hlist_node *tmp;
		struct route_entry *re;

	       	rb = rt->buckets + i;

		spin_lock_bh(&rb->lock);
		hash_for_each_safe(rb->head, bkt, tmp, re, node) {
			route_entry_release(re);
		}
		spin_unlock_bh(&rb->lock);
	}
}

void route_table_uninit(struct route_table *rt)
{
	route_table_clear(rt);
	kfree(rt);
}

static void route_entry_timer_cb(unsigned long data)
{
	struct route_entry *re;

	re = (struct route_entry *)data;
	spin_lock(&re->rb->lock);
	route_entry_release(re);
	spin_unlock(&re->rb->lock);
}

int route_table_add_expire(struct route_table *rt, __be32 network,
		unsigned char mask, int secs)
{
	struct route_entry *re;
	struct route_bucket *rb;

	re = kzalloc(sizeof *re, GFP_ATOMIC);
	if (!re) {
		LOG_ERROR("failed to alloc route entry");
		return -ENOMEM;
	}

	re->rb = rt->buckets + (32 - mask);
	re->network = network;
	setup_timer(&re->timer, route_entry_timer_cb, (unsigned long)re);

	rb = re->rb;
	spin_lock_bh(&rb->lock);
	rb->size++;
	hash_add_rcu(rb->head, &re->node, re->network);
	if (!secs)
		mod_timer(&re->timer, jiffies + secs * HZ);
	spin_unlock_bh(&rb->lock);

	return 0;
}

int route_table_add(struct route_table *rt, __be32 network,
		unsigned char mask)
{
	return route_table_add_expire(rt, network, mask, 0);
}

int route_table_add_delete(struct route_table *rt, __be32 network,
		unsigned char mask)
{
	struct route_bucket *rb;
	struct hlist_node *tmp;
	struct route_entry *re;

	rb = rt->buckets + (32 - mask);

	spin_lock_bh(&rb->lock);
	hash_for_each_possible_safe(rb->head, re, tmp, node, network)
		if (re->network == network) {
			route_entry_release(re);
		}
	spin_unlock_bh(&rb->lock);

	return 0;
}

bool route_table_contains(struct route_table *rt, __be32 ip)
{
	int i;

	for (i = 0; i < ROUTE_BUCKET_NR; i++) {
		struct route_bucket *rb;
		struct route_entry *re;
		__be32 key;

		rb = rt->buckets + i;
		if (rb->size == 0)
			continue;

		key = ip & rb->mask;
		rcu_read_lock();
		hash_for_each_possible_rcu(rb->head, re, node, key)
			if (re->network == key) {
				rcu_read_unlock();
				return true;
			}
		rcu_read_unlock();
	}
	return false;
}
