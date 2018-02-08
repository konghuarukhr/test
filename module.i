static struct sock *sk = NULL;

static int __net_init iproxy_net_init(struct net *net)
{
	int err;

	err = nf_register_net_hooks(net, iproxy_nf_ops,
			ARRAY_SIZE(iproxy_nf_ops));
	if (err) {
		LOG_ERROR("failed to register nf hooks: %d", err);
		goto nf_register_net_hooks_err;
	}

	sk = netlink_kernel_create(net, NETLINK_GENERIC, &iproxy_nl_cfg);
	if (!sk) {
		err = -ENOMEM;
		LOG_ERROR("failed to create netlink");
		goto netlink_kernel_create_err;
	}

	return 0;

netlink_kernel_create_err:
	nf_unregister_net_hooks(net, iproxy_nf_ops, ARRAY_SIZE(iproxy_nf_ops));

nf_register_net_hooks_err:

	return err;
}

static int __net_exit iproxy_net_exit(struct net *net)
{
	netlink_kernel_release(sk);

	nf_unregister_net_hooks(net, iproxy_nf_ops, ARRAY_SIZE(iproxy_nf_ops));
}

static struct pernet_operations __net_initdata iproxy_net_ops = {
	.init = iproxy_net_init;
	.exit = iproxy_net_exit;
};

static int __init iproxy_init(void)
{
	int err;

	LOG_INFO("initing...");

	err = params_init();
	if (err) {
		LOG_ERROR("failed to init input params: %d", err);
		goto params_init_err;
	}

	err = register_pernet_device(&iproxy_net_ops);
	if (err) {
		LOG_ERROR("failed to register net namespace: %d", err);
		goto register_pernet_device_err;
	}

	LOG_INFO("inited");

	return 0;

register_pernet_device_err:
	params_deinit();

params_init_err:

	LOG_ERROR("exited");

	return err;
}

static void __exit iproxy_exit(void)
{
	LOG_INFO("exiting...");

	unregister_pernet_device(&iproxy_net_ops);

	params_deinit();

	LOG_INFO("exited");
}

module_init(iproxy_init);
module_exit(iproxy_exit);

MODULE_LICENSE(LICENSE);
MODULE_ALIAS(ALIAS);
MODULE_DESCRIPTION(DESCRIPTION);
MODULE_VERSION(VERSION);
MODULE_AUTHOR(AUTHOR);
