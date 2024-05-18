#include "probes/probes.h"
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
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "libs/scth.h"
#include "reference_monitor.h"
#include "utils/crypto.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alessandro Lioi <alessandro.lioi@students.uniroma2.it>");
MODULE_DESCRIPTION("Reference Monitor");

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

unsigned long the_ni_syscall;
unsigned long new_sys_call_array[] = {0x0, 0x0, 0x0, 0x0};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array) / sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ...(HACKED_ENTRIES - 1)] = -1};

extern long sys_reference_monitor_change_password;
extern long sys_reference_monitor_set_state;
extern long sys_reference_monitor_add_path;
extern long sys_reference_monitor_delete_path;

struct reference_monitor refmon = {0};

int init_module(void) {
  // Variable Declaration
  int i, ret;

  printk("%s: init\n", MODNAME);

  // System Call Initialization
  if (the_syscall_table == 0x0) {
    printk("%s: cannot manage sys_call_table address set to 0x0\n", MODNAME);
    return -1;
  }
  new_sys_call_array[0] = (unsigned long)sys_reference_monitor_change_password;
  new_sys_call_array[1] = (unsigned long)sys_reference_monitor_set_state;
  new_sys_call_array[2] = (unsigned long)sys_reference_monitor_add_path;
  new_sys_call_array[3] = (unsigned long)sys_reference_monitor_delete_path;
  ret = get_entries(restore, HACKED_ENTRIES, (unsigned long *)the_syscall_table, &the_ni_syscall);
  if (ret != HACKED_ENTRIES) {
    printk("%s: could not hack %d entries (just %d)\n", MODNAME, HACKED_ENTRIES, ret);
    return -1;
  }
  unprotect_memory();

  for (i = 0; i < HACKED_ENTRIES; i++) {
    ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
  }

  protect_memory();

  printk("%s: all new system-calls correctly installed on sys-call table\n", MODNAME);

  // Reference Monitor initialization
  refmon.state = REFMON_STATE_OFF;
  refmon.password_hash = kmalloc(sizeof(*refmon.password_hash) * 32, GFP_KERNEL);
  if (refmon.password_hash == NULL) {
    printk(KERN_ERR "failed to allocate password_hash\n");
    return -ENOMEM;
  }
  refmon.password_hash = crypt_data("reference_monitor_default_password");
  if (refmon.password_hash == NULL) {
    printk(KERN_ERR "failed to crypt_data for default password\n");
    return -ENOMEM;
  }
  INIT_LIST_HEAD(&refmon.paths.list);

  probes_init();
  printk("%s: correctly initialized\n", MODNAME);

  return 0;
}

void cleanup_module(void) {
  // Variable Declaration
  int i;

  printk("%s: cleanup\n", MODNAME);

  // System Call Cleanup
  unprotect_memory();
  for (i = 0; i < HACKED_ENTRIES; i++) {
    ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
  }
  protect_memory();

  // Reference Monitor Cleanup
  kfree(refmon.password_hash);
  // Unregister probes if they were enabled
  if (refmon.state == REFMON_STATE_ON)
    probes_unregister();

  printk("%s: sys-call table restored to its original content\n", MODNAME);
}
