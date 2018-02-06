struct network {
	struct hlist_node;
	__be32 addr;
};

static struct network unproxy_network_array[32];
static struct hlist_head **

void init()
{
	for (int i = 0; i < N; i++) {
		unproxy_network_array[i].hlist_node.first = NULL;
	}
}

static DEFINE_READ_MOSTLY_HASHTABLE(napi_hash, 8);


void insert(__be32 addr, int mask)
{
	struct network *network = kzalloc(sizeof *network, GFP_KERNEL);
	if (!network)
		return -ENOMEM;

	ele = &unproxy_network_array[mask];
	network->addr = addr;
	hlist_add_head_rcu(&network->hlist_node, unproxy_network_array[mask]);
}


bool lookup(__be32 addr)
{
	hlist_for_each_entry_rcu(napi, &napi_hash[hash], napi_hash_node) {
	}
}
