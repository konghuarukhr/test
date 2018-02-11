#define ROUTE_HT_BITS 10
#define ROUTE_TBL_SIZE 25 // mask: 8-32

struct route_ent {
	__be32 network;
	struct timer_list timer;
	struct hlist_node node;
};

struct route_tbl {
	DECLARE_HASHTABLE(head, ROUTE_HT_BITS);
	__be32 mask;
	int size;
};

struct route_tbl route_tbl[ROUTE_TBL_SIZE];

void route_tbl_init(void)
{
	for (int i = 0; i < ROUTE_TBL_SIZE; i++) {
		struct route_tbl *rt = &route_tbl[i];
		hash_init(rt->head);
		rt->mask = htonl(-(1 << i));
		rt->size = 0;
	}
}

struct route_ent *route_tbl_add(__be32 network, unsigned char mask)
{
	struct route_ent *re = kmalloc(sizeof *re, GFP_KERNEL);
	if (!re)
		return NULL;
	re->network = network;
	init_timer(&re->timer);

	struct route_tbl *rt = &route_tbl[32 - mask];
	hash_add(rt->head, &re->node, re->network);
	rt->size++;
	return re;
}

void route_ent_release(struct route_ent *re)
{
	__hlist_del(re->node);
	kfree(re);
}

void route_ent_expire(unsigned long data)
{
	struct route_ent *re = (struct route_ent *)data;
	__hlist_del(re->node);
	kfree(re);
}

bool route_tbl_add_expire(__be32 network, unsigned char mask, int secs)
{
	struct route_ent *re = kmalloc(sizeof *re, GFP_KERNEL);
	if (!re)
		return NULL;
	re->network = network;
	init_timer(&re->timer);
	re->timer.expires = jiffies + secs * HZ;
	re->timer.function = route_ent_expire;
	re->timer.data = re;

	struct route_tbl *rt = &route_tbl[32 - mask];
	hash_add(rt->head, &re->node, re->network);
	rt->size++;
	return re;
}


void route_tbl_init(__be32 *network, int *mask, int size)
{
	for (int i = 0; i < ROUTE_TBL_SIZE; i++) {
		struct route_tbl *rt = &route_tbl[i];
		rt->mask = htonl(-(2 << i));
		rt->size = 0;
	}

	for (int i = 0; i < size; i++) {
		struct route_tbl *rt = &route_tbl[32 - mask[i]];
		struct route_ent *re = kmalloc(sizeof *re, GFP_KERNEL);
		re->network = network[i];
		hash_add(rt->route_ent, &re->node, re->network);
		rt->size++;
	}
}

void route_tbl_uninit(void)
{
	for (int i = 0; i < ROUTE_TBL_SIZE; i++) {
		struct route_tbl *rt = &route_tbl[i];
		struct hlist_node *p, *n;
		hlist_for_each_safe(p, n, &rt->route_ent) {
			__hlist_del(p);
			struct route_ent *re = hlist_entry(p,
					struct route_ent, node);
			kfree(re);
		}
		rt->size = 0;
	}
}

struct route_ent *lookup_route_ent(__be32 ip)
{
	for (int i = 0; i < ROUTE_TBL_SIZE; i++) {
		if (route_tbl[i].size == 0)
			continue;
		__be32 key = ip & mask;
		struct route_ent *re;
		hash_for_each_possible(route_tbl[i].route_ent, re, node, key)
			if (re->network == key)
				return re;
	}
}

static DEFINE_MUTEX(ipr_rcv_mutex);

static int nl_ipr_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh,
		struct netlink_ext_ack *extack)
{
}

static void nl_ipr_rcv(struct sk_buff *skb)
{
	mutex_lock(&ipr_rcv_mutex);
	netlink_rcv_skb(skb, nl_ipr_rcv_msg);
	mutex_unlock(&ipr_rcv_mutex);
}

static struct pernet_operations iproxy_net_ops = {
	.init = net_init;
	.exit = net_exit;
};

static net_init(struct net *net)
{
	struct netlink_kernel_cfg cfg = {
		.input  = nl_rcv,
	};
	struct sock *sk = netlink_kernel_create(net, NETLINK_NETFILTER, &cfg);
	if (!sk) {
	}
}
