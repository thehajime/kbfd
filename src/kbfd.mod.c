#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
};

static const struct modversion_info ____versions[]
__attribute_used__
__attribute__((section("__versions"))) = {
	{ 0x8214aa57, "struct_module" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x6c671f55, "ip_route_output_key" },
	{ 0x79aa04a2, "get_random_bytes" },
	{ 0xb07dc511, "sock_release" },
	{ 0x1bcd461f, "_spin_lock" },
	{ 0x9d953db, "sock_recvmsg" },
	{ 0xbade5b27, "remove_proc_entry" },
	{ 0xd16ac615, "__get_user_1" },
	{ 0x1d26aa98, "sprintf" },
	{ 0x7d11c268, "jiffies" },
	{ 0xc102b156, "cancel_rearming_delayed_workqueue" },
	{ 0x7f1a3bd2, "__create_workqueue" },
	{ 0xa34eb072, "wait_for_completion" },
	{ 0x7aad66d0, "netlink_kernel_create" },
	{ 0x228dfa92, "proc_mkdir" },
	{ 0x1b7d4074, "printk" },
	{ 0x859204af, "sscanf" },
	{ 0x5152e605, "memcmp" },
	{ 0xe0b3b35b, "sock_sendmsg" },
	{ 0xe7974241, "destroy_workqueue" },
	{ 0xd7dd2476, "dev_get_by_index" },
	{ 0x6091797f, "synchronize_rcu" },
	{ 0xd79b5a02, "allow_signal" },
	{ 0x59b9804b, "ip6_route_output" },
	{ 0xb867d1bd, "skb_over_panic" },
	{ 0x93f4998b, "__alloc_skb" },
	{ 0x581d2a09, "netlink_broadcast" },
	{ 0x424c8b46, "kfree_skb" },
	{ 0x6b2dc060, "dump_stack" },
	{ 0x3b2d7067, "create_proc_entry" },
	{ 0x17b0ce40, "netlink_ack" },
	{ 0x1720c84e, "proc_root" },
	{ 0xd0b91f9b, "init_timer" },
	{ 0x85e5a3db, "ktime_get_ts" },
	{ 0xe599ea7b, "sched_setscheduler" },
	{ 0x5fc0f501, "netlink_dump_start" },
	{ 0x37a0cba, "kfree" },
	{ 0x932da67e, "kill_proc" },
	{ 0x682d771d, "sock_create" },
	{ 0x7e9ebb05, "kernel_thread" },
	{ 0x66994e6f, "skb_dequeue" },
	{ 0x7e0221e4, "complete" },
	{ 0x9e485b4c, "queue_delayed_work" },
	{ 0x15792c26, "__ipv6_addr_type" },
	{ 0xdc43a9c8, "daemonize" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=ipv6";

