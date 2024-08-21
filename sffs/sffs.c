#define EXPORT_SYMTAB

#include <asm/apic.h>
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/page.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "sffs.h"
#include "src/fs.h"

struct file_system_type fs_type = {
    .owner = THIS_MODULE,
    .name = "sffs",
    .mount = fs_mount,
    .kill_sb = fs_kill_sb,
};

static int sffs_init(void) {
  int ret = 0;

  pr_info("%s: init\n", MODNAME);

  ret = register_filesystem(&fs_type);
  if (unlikely(ret != 0))
    pr_err("%s: register_filesystem failed in init_module\n", MODNAME);

  pr_info("%s: fs init successful\n", MODNAME);
  return ret;
}

static void sffs_cleanup(void) {
  int ret = 0;

  pr_info("%s: cleanup\n", MODNAME);

  ret = unregister_filesystem(&fs_type);

  if (unlikely(ret != 0))
    pr_err("%s: unregister_filesystem failed in cleanup_module\n", MODNAME);
}

module_init(sffs_init);
module_exit(sffs_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alessandro Lioi <alessandro.lioi@students.uniroma2.it>");
MODULE_DESCRIPTION("Single File FS");
