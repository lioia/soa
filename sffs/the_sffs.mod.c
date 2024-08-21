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
	{ 0x6ad771c3, "module_layout" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0xc1d76ca9, "_copy_from_iter" },
	{ 0xd9b85ef6, "lockref_get" },
	{ 0x3213f038, "mutex_unlock" },
	{ 0x301bc87c, "mount_bdev" },
	{ 0x699d22b2, "d_add" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xdee72273, "__bread_gfp" },
	{ 0x9ec6ca96, "ktime_get_real_ts64" },
	{ 0x4dfa8d4b, "mutex_lock" },
	{ 0x4862983c, "set_nlink" },
	{ 0x3af226bd, "__brelse" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x92997ed8, "_printk" },
	{ 0x12160631, "unlock_new_inode" },
	{ 0x60423cc2, "kill_block_super" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x1eb5a597, "register_filesystem" },
	{ 0x6d544437, "iput" },
	{ 0x37a0cba, "kfree" },
	{ 0x69acdf38, "memcpy" },
	{ 0xe8568e92, "d_make_root" },
	{ 0x92f8eba0, "mark_buffer_dirty" },
	{ 0x45eadf33, "unregister_filesystem" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x2ca2c90b, "iget_locked" },
	{ 0xebbb5688, "inode_init_owner" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "5076D3E200F648DA35BCF12");
