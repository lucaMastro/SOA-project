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
	{ 0x11caad4a, "sys_call_helper" },
	{ 0x37a0cba, "kfree" },
	{ 0x2782e7c5, "crypto_shash_digest" },
	{ 0x356d8995, "crypto_destroy_tfm" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x3e358609, "crypto_alloc_shash" },
	{ 0xe914e41e, "strcpy" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x92997ed8, "_printk" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xd45cc6ca, "bin2hex" },
	{ 0x93170f4f, "reference_monitor" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "the_usctm,reference_monitor");


MODULE_INFO(srcversion, "75583D9A02870DA6FF7014D");
