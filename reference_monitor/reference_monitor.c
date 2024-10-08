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
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "libs/scth.h"
#include "probes/probes.h"
#include "reference_monitor.h"
#include "utils/utils.h"

char *password = NULL;
module_param(password, charp, 0000);

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

// Allocation of reference monitor struct
struct reference_monitor refmon = {0};

/**
 * @brief Init function of the reference monitor
 *
 * @return non-zero on error
 */
static int reference_monitor_init(void) {
  // Variable Declaration
  int i, ret;

  pr_info("%s: init\n", MODNAME);

  // System Call Initialization
  if (the_syscall_table == 0x0) {
    pr_err("%s: cannot manage sys_call_table address set to 0x0\n", MODNAME);
    return -1;
  }
  new_sys_call_array[0] = (unsigned long)sys_reference_monitor_change_password;
  new_sys_call_array[1] = (unsigned long)sys_reference_monitor_set_state;
  new_sys_call_array[2] = (unsigned long)sys_reference_monitor_add_path;
  new_sys_call_array[3] = (unsigned long)sys_reference_monitor_delete_path;
  ret = get_entries(restore, HACKED_ENTRIES, (unsigned long *)the_syscall_table, &the_ni_syscall);
  if (ret != HACKED_ENTRIES) {
    pr_err("%s: could not hack %d entries (just %d)\n", MODNAME, HACKED_ENTRIES, ret);
    return -1;
  }
  unprotect_memory();

  for (i = 0; i < HACKED_ENTRIES; i++) {
    ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
  }

  protect_memory();

  pr_info("%s: all new system-calls correctly installed on sys-call table\n", MODNAME);

  // Reference Monitor initialization
  refmon.state = RM_OFF; // Initial state is inactive
  refmon.password_hash = kmalloc(sizeof(*refmon.password_hash) * SHA_LENGTH, GFP_KERNEL);
  if (refmon.password_hash == NULL) {
    pr_err(KERN_ERR "failed to allocate password_hash\n");
    return -ENOMEM;
  }
  refmon.password_hash = crypt_data(password, false);
  if (refmon.password_hash == NULL) {
    pr_err(KERN_ERR "failed to crypt_data for default password\n");
    return -ENOMEM;
  }

  spin_lock_init(&refmon.lock); // Initialize lock used for editing the RCU list
  INIT_LIST_HEAD(&refmon.list); // Initialize the RCU list of protected paths
  probes_init();                // Initialize probes
  ret = probes_disable();       // State is OFF -> probes are disabled
  if (ret != 0) {
    pr_info("%s: probes_disable failed\n", MODNAME);
    return ret;
  }

  pr_info("%s: correctly initialized\n", MODNAME);

  return ret;
}

/**
 * @brief Cleanup function of the reference monitor module
 */
static void reference_monitor_cleanup(void) {
  // Variable Declaration
  int i = 0;
  struct reference_monitor_path *node = NULL;

  // Reference Monitor Cleanup
  kfree(refmon.password_hash);
  if (refmon.state == RM_ON || refmon.state == RM_REC_ON)
    probes_disable(); // Reference Monitor is active -> disable probes
  probes_deinit();    // Deregister probes

  // Free all paths
  spin_lock(&refmon.lock); // Editing RCU List, lock is required
  rcu_read_lock();         // Traversing List
  list_for_each_entry_rcu(node, &refmon.list, next) {
    list_del_rcu(&node->next); // Remove node
    kfree(node);               // Free memory of node
  }
  // Unlock locks
  rcu_read_unlock();
  spin_unlock(&refmon.lock);

  pr_info("%s: cleanup\n", MODNAME);

  // System Call Cleanup
  unprotect_memory();
  for (i = 0; i < HACKED_ENTRIES; i++) {
    ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
  }
  protect_memory();

  pr_info("%s: sys-call table restored to its original content\n", MODNAME);
}

module_init(reference_monitor_init);
module_exit(reference_monitor_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alessandro Lioi <alessandro.lioi@students.uniroma2.it>");
MODULE_DESCRIPTION("Reference Monitor");
