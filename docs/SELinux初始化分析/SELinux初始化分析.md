# SE Linux初始化分析

全局变量

```c

struct selinux_state selinux_state;

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
static int selinux_enforcing_boot __initdata;

static int __init enforcing_setup(char *str)
{
	unsigned long enforcing;
	if (!kstrtoul(str, 0, &enforcing))
		selinux_enforcing_boot = enforcing ? 1 : 0;
	return 1;
}
__setup("enforcing=", enforcing_setup);
#else
#define selinux_enforcing_boot 1
#endif
```




```c
static __init int selinux_init(void)
{
	pr_info("SELinux:  Initializing.\n");

	memset(&selinux_state, 0, sizeof(selinux_state));
	enforcing_set(selinux_enforcing_boot);
	selinux_avc_init();
	mutex_init(&selinux_state.status_lock);
	mutex_init(&selinux_state.policy_mutex);

	/* Set the security state for the initial task. */
	cred_init_security();

	default_noexec = !(VM_DATA_DEFAULT_FLAGS & VM_EXEC);
	if (!default_noexec)
		pr_notice("SELinux:  virtual memory is executable by default\n");

	avc_init();

	avtab_cache_init();

	ebitmap_cache_init();

	hashtab_cache_init();

	security_add_hooks(selinux_hooks, ARRAY_SIZE(selinux_hooks), "selinux");

	if (avc_add_callback(selinux_netcache_avc_callback, AVC_CALLBACK_RESET))
		panic("SELinux: Unable to register AVC netcache callback\n");

	if (avc_add_callback(selinux_lsm_notifier_avc_callback, AVC_CALLBACK_RESET))
		panic("SELinux: Unable to register AVC LSM notifier callback\n");

	if (selinux_enforcing_boot)
		pr_debug("SELinux:  Starting in enforcing mode\n");
	else
		pr_debug("SELinux:  Starting in permissive mode\n");

	fs_validate_description("selinux", selinux_fs_parameters);

	return 0;
}

/* SELinux requires early initialization in order to label
   all processes and objects when they are created. */
DEFINE_LSM(selinux) = {
	.name = "selinux",
	.flags = LSM_FLAG_LEGACY_MAJOR | LSM_FLAG_EXCLUSIVE,
	.enabled = &selinux_enabled_boot,
	.blobs = &selinux_blob_sizes,
	.init = selinux_init,
};

```