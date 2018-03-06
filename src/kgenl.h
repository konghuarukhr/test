#ifndef _KGENL_H_
#define _KGENL_H_

#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/genetlink.h>
#include "route.h"
#include "ugenl.h"


static struct route_table *route_table = NULL;

static int clear_route(struct sk_buff *skb, struct genl_info *info)
{
	route_table_clear(route_table);
	return 0;
}

static int add_route(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *network_attr = info->attrs[IPR_ATTR_NETWORK];
	struct nlattr *mask_attr = info->attrs[IPR_ATTR_MASK];
	if (network_attr && mask_attr) {
		__be32 network = nla_get_be32(network_attr);
		__u8 mask = nla_get_u8(mask_attr);
		route_table_add(route_table, network, mask);
		return 0;
	}
	return -EINVAL;
}

static int delete_route(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *network_attr = info->attrs[IPR_ATTR_NETWORK];
	struct nlattr *mask_attr = info->attrs[IPR_ATTR_MASK];
	if (network_attr && mask_attr) {
		__be32 network = nla_get_be32(network_attr);
		__u8 mask = nla_get_u8(mask_attr);
		route_table_delete(route_table, network, mask);
		return 0;
	}
	return -EINVAL;
}

static int show_route(struct sk_buff *skb, struct genl_info *info)
{
	return -ENOTSUPP;
}

static struct nla_policy iproxy_genl_policy[IPR_ATTR_MAX + 1] = {
	[IPR_ATTR_NETWORK] = {.type = NLA_U32},
	[IPR_ATTR_MASK] = {.type = NLA_U8},
};

static const struct genl_ops iproxy_genl_ops[] = {
	{
		.cmd = IPR_CMD_CLEAR_ROUTE,
		.doit = clear_route,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPR_CMD_ADD_ROUTE,
		.doit = add_route,
		.policy = iproxy_genl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPR_CMD_DELETE_ROUTE,
		.doit = delete_route,
		.policy = iproxy_genl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPR_CMD_SHOW_ROUTE,
		.doit = show_route,
	},
};

static struct genl_family iproxy_genl_family = {
	.name = GENL_FAMILY_NAME,
	.version = 0x02,
	.maxattr = IPR_ATTR_MAX,
	.netnsok = true,
	.ops = iproxy_genl_ops,
	.n_ops = ARRAY_SIZE(iproxy_genl_ops),
	.module = THIS_MODULE,
};

#endif
