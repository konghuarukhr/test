#define ROUTE_HT_BITS 10
#define ROUTE_TBL_SIZE 25 // mask: 8-32

struct route_entry {
	__be32 network;
	struct hlist_node node;
};

struct route_tbl {
	DEFINE_READ_MOSTLY_HASHTABLE(route_entry, ROUTE_HT_BITS);
	__be32 mask;
	int size;
};

struct route_tbl route_tbl[ROUTE_TBL_SIZE];

void route_tbl_init(__be32 *network, int *mask, int size)
{
	for (int i = 0; i < ROUTE_TBL_SIZE; i++) {
		struct route_tbl *rt = &route_tbl[i];
		rt->mask = htonl(-(2 << i));
		rt->size = 0;
	}

	for (int i = 0; i < size; i++) {
		struct route_tbl *rt = &route_tbl[32 - maks[i]];
		struct route_entry *re = kmalloc(sizeof *re, GFP_KERNEL);
		re->network = network[i];
		hash_add(rt->route_entry, &re->node, re->network);
		rt->size++;
	}
}

void route_tbl_deinit(void)
{
	for (int i = 0; i < ROUTE_TBL_SIZE; i++) {
		struct route_tbl *rt = &route_tbl[i];
		struct hlist_node *p, *n;
		hlist_for_each_safe(p, n, &rt->route_entry) {
			__hlist_del(p);
			struct route_entry *re = hlist_entry(p,
					struct route_entry, node);
			kfree(re);
		}
		rt->size = 0;
	}
}

struct route_entry *lookup_route_entry(__be32 ip)
{
	for (int i = 0; i < ROUTE_TBL_SIZE; i++) {
		if (route_tbl[i].size == 0)
			continue;
		__be32 key = ip & mask;
		struct route_entry *re;
		hash_for_each_possible(route_tbl[i].route_entry, re, node, key)
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
