#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xcd6bb128, "module_layout" },
	{ 0x37a0cba, "kfree" },
	{ 0x63026490, "unregister_kprobe" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0xc8dcc62a, "krealloc" },
	{ 0x2fd729f4, "filp_close" },
	{ 0x5d9e4a50, "kernel_read" },
	{ 0xc22521c7, "filp_open" },
	{ 0x3480d929, "kmem_cache_alloc_trace" },
	{ 0x6f029675, "kmalloc_caches" },
	{ 0xfcca5424, "register_kprobe" },
	{ 0x92997ed8, "_printk" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "988C56FAF52E8072CCB199A");
