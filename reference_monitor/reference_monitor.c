#include "linux/printk.h"
#define EXPORT_SYMTAB

#include <asm/apic.h>
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/page.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alessandro Lioi <alessandro.lioi@students.uniroma2.it>");
MODULE_DESCRIPTION("Reference Monitor");

#define MODNAME "REFMON"

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

int init_module(void) {
  printk("%s: init\n", MODNAME);
  return 0;
}

void cleanup_module(void) { printk("%s: cleanup\n", MODNAME); }
