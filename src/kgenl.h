#ifndef _KGENL_H_
#define _KGENL_H_

#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/genetlink.h>
#include "route.h"
#include "ugenl.h"


static struct route_table *route_table;
static struct genl_family iproxy_genl_family;

static int clear_route(struct sk_buff *skb, struct genl_info *info)
{
	LOG_DEBUG("in");
	route_table_clear(route_table);
	LOG_DEBUG("out");
	return 0;
}

static int add_route(struct sk_buff *skb, struct genl_info *info)
{
	LOG_DEBUG("");
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
	LOG_DEBUG("");
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
	LOG_DEBUG("");
	return -ENOTSUPP;
}

static int find_route(struct sk_buff *skb_in, struct genl_info *info)
{
	LOG_DEBUG("");
	int err;
	struct sk_buff *skb_out;
	struct nlattr *network_attr = info->attrs[IPR_ATTR_NETWORK];
	if (!network_attr) {
		err = -EINVAL;
		goto network_attr_err;
	}

	__be32 network = nla_get_be32(network_attr);
	__u8 mask = route_table_get_mask(route_table, network);

	skb_out = genlmsg_new(nla_total_size(sizeof(__u8)), GFP_KERNEL);
	if (!skb_out) {
		err = -ENOMEM;
		goto genlmsg_new_err;
	}

	void *msg_head = genlmsg_put(skb_out, NETLINK_CB(skb_in).portid,
			info->snd_seq, &iproxy_genl_family, 0,
			IPR_CMD_GET_ROUTE);
	if (!msg_head) {
		err = -EMSGSIZE;
		goto genlmsg_put_err;
	}

	err = nla_put_u8(skb_out, IPR_ATTR_MASK, mask);
	if (err) {
		goto nla_put_mask_err;
	}

	genlmsg_end(skb_out, msg_head);
	genlmsg_unicast(genl_info_net(info), skb_out, info->snd_portid);

	return 0;

nla_put_mask_err:
genlmsg_put_err:
	nlmsg_free(skb_out);
genlmsg_new_err:
network_attr_err:
	//netlink_ack(skb_in, nlmsg_hdr(skb_in), -EINVAL, NULL);
	return err;
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
	{
		.cmd = IPR_CMD_GET_ROUTE,
		.doit = find_route,
		.policy = iproxy_genl_policy,
	},
};

static struct genl_family iproxy_genl_family = {
	.name = IPR_GENL_NAME,
	.version = 0x02,
	.maxattr = IPR_ATTR_MAX,
	.netnsok = true,
	.ops = iproxy_genl_ops,
	.n_ops = ARRAY_SIZE(iproxy_genl_ops),
	.module = THIS_MODULE,
};

#endif
