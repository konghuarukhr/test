static int iproxy_net_init(struct net *net)
{
	err = nf_register_net_hooks(&iproxy_net_ops, iproxy_nf_ops,
			ARRAY_SIZE(iproxy_nf_ops));
	if (err) {
		LOG_ERROR("failed to regist nf hooks: %d", err);
		goto nf_register_net_hooks_err;
	}

}

static int iproxy_net_exit()

static struct pernet_operations iproxy_net_ops = {
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

	err = nf_register_net_hooks(&iproxy_net_ops, iproxy_nf_ops,
			ARRAY_SIZE(iproxy_nf_ops));
	if (err) {
		LOG_ERROR("failed to regist nf hooks: %d", err);
		goto nf_register_net_hooks_err;
	}

	struct sock *sk = netlink_kernel_create(&iproxy_net_ops,
			NETLINK_NETFILTER, &cfg);
	if (!sk) {
		LOG_ERROR("failed to create netlink");
		goto netlink_kernel_create_err;
	}

	LOG_INFO("inited");

	return 0;

netlink_kernel_create_err:
	nf_unregister_net_hooks(&init_net, iproxy_ops, ARRAY_SIZE(iproxy_ops));

nf_register_net_hooks_err:
	unregister_pernet_device(&unregister_pernet_device);

register_pernet_device_err:
	params_deinit();

params_init_err:
	LOG_ERROR("exited");

	return err;
}

static void __exit iproxy_exit(void)
{
	LOG_INFO("exiting...");

	nf_unregister_net_hooks(&init_net, iproxy_nf_ops, ARRAY_SIZE(iproxy_nf_ops));

	LOG_INFO("exited");
}

module_init(iproxy_init);
module_exit(iproxy_exit);

MODULE_LICENSE(LICENSE);
MODULE_ALIAS(ALIAS);
MODULE_DESCRIPTION(DESCRIPTION);
MODULE_VERSION(VERSION);
MODULE_AUTHOR(AUTHOR);
