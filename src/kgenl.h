#ifndef _KGENL_H_
#define _KGENL_H_

#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/genetlink.h>
#include "route.h"
#include "ugenl.h"


static struct route_table *route_table;

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

static int find_route(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	struct sk_buff *skb2;
	struct nlattr *network_attr = info->attrs[IPR_ATTR_NETWORK];
	if (!network_attr) {
		err = -EINVAL;
		goto network_attr_err;
	}

	__be32 network = nla_get_be32(network_attr);
	__u8 mask = route_table_get_mask(route_table, network);

	skb2 = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb2) {
		err = -ENOMEM;
		goto genlmsg_new_err;
	}

/*构建消息头，函数原型是 
        genlmsgput(struct sk_buff *,int pid,int seq_number, 
                struct genl_family *,int flags,u8 command_index); 
        */ 
	msg_head = genlmsg_put(skb_out, NETLINK_CB(skb_in).portid,
			info->snd_seq, &iproxy_genl_family, 0,
			IPR_CMD_GET_ROUTE);
	if (!msg_head) {
	}
	genlmsg_put(skb2, 0, info->snd_seq+1, &doc_exmpl_genl_family,0,DOC_EXMPL_C_ECHO);
if(msg_hdr == NULL){  
                rc = -ENOMEM;  
                goto error;  
        }  
  
        //填充具体的netlink attribute:DOC_EXMPL_A_MSG，这是实际要传的数据  
        rc = nla_put_string(skb,DOC_EXMPL_A_MSG,"Hello World from kernel space!");  
        if(rc != 0) goto error;  
  
        genlmsg_end(skb,msg_hdr);//消息构建完成  
        //单播发送给用户空间的某个进程  
        rc = genlmsg_unicast(genl_info_net(info),skb,info->snd_pid);  
        if(rc != 0){  
                printk("Unicast to process:%d failed!\n",info->snd_pid);  
                goto error;  
        }  
        return 0; 
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
		.doit = get_route,
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
