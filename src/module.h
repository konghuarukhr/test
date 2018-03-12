static int __net_init iproxy_net_init(struct net *net)
{
	int err;

	err = nf_register_net_hooks(net, iproxy_nf_ops,
			ARRAY_SIZE(iproxy_nf_ops));
	if (err) {
		LOG_ERROR("failed to register nf hooks: %d", err);
		goto nf_register_net_hooks_err;
	}

	err = genl_register_family(&iproxy_genl_family);
	if (err) {
		LOG_ERROR("failed to register genl family: %d", err);
		goto genl_register_family_err;
	}

#ifdef SERVER /* or client on router */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
	nf_defrag_ipv4_enable();
#else
	err = nf_defrag_ipv4_enable(net);
	if (err) {
		LOG_ERROR("failed to enable ipv4 defrag: %d", err);
		goto nf_defrag_ipv4_enable_err;
	}
#endif
#endif

	return 0;

#ifdef SERVER /* or client on router */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
nf_defrag_ipv4_enable_err:
#endif
#endif

genl_register_family_err:
	nf_unregister_net_hooks(net, iproxy_nf_ops, ARRAY_SIZE(iproxy_nf_ops));

nf_register_net_hooks_err:

	return err;
}

static void __net_exit iproxy_net_exit(struct net *net)
{
	genl_unregister_family(&iproxy_genl_family);

	nf_unregister_net_hooks(net, iproxy_nf_ops, ARRAY_SIZE(iproxy_nf_ops));
}

static struct pernet_operations __net_initdata iproxy_net_ops = {
	.init = iproxy_net_init,
	.exit = iproxy_net_exit,
};

static int __init iproxy_init(void)
{
	int err;

	LOG_INFO("initing...");

	err = custom_init();
	if (err) {
		LOG_ERROR("failed to do custom init: %d", err);
		goto custom_init_err;
	}

	err = register_pernet_subsys(&iproxy_net_ops);
	if (err) {
		LOG_ERROR("failed to register net namespace: %d", err);
		goto register_pernet_device_err;
	}

	LOG_INFO("inited");

	return 0;

register_pernet_device_err:
	custom_uninit();

custom_init_err:

	LOG_ERROR("exited");

	return err;
}

static void __exit iproxy_exit(void)
{
	LOG_INFO("exiting...");

	unregister_pernet_subsys(&iproxy_net_ops);

	custom_uninit();

	LOG_INFO("exited");
}

module_init(iproxy_init);
module_exit(iproxy_exit);

MODULE_LICENSE(LICENSE);
MODULE_ALIAS(ALIAS);
MODULE_DESCRIPTION(DESCRIPTION);
MODULE_VERSION(VERSION);
MODULE_AUTHOR(AUTHOR);
