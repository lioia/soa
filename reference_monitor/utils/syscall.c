#include <linux/err.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/limits.h>
#include <linux/printk.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>

#include "../probes/probes.h"
#include "../reference_monitor.h"
#include "crypto.h"
#include "utils.h"

extern struct reference_monitor refmon;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _reference_monitor_change_password, const char *, password, const char *, old_password) {
#else
asmlinkage long sys_reference_monitor_change_password(const char *password, const char *old_password) {
#endif
  char *buffer = NULL;
  long ret = 0;

  printk(KERN_INFO "%s: change_password\n", MODNAME);
  if ((ret = is_root_and_correct_password(old_password)) < 0)
    goto exit;

  if (copy_from_user(buffer, password, PASSWORD_MAX_LEN) < 0) {
    printk("%s: error copy_from_user (password) in syscall change_password\n", MODNAME);
    ret = -EINVAL;
    goto exit;
  }
  refmon.password_hash = crypt_data(buffer);

exit:
  if (buffer)
    kfree(buffer);
  return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_reference_monitor_change_password = (unsigned long)__x64_sys_reference_monitor_change_password;
#else
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _reference_monitor_set_state, const char *, password, int, state) {
#else
asmlinkage long sys_reference_monitor_set_state(const char *password, int state) {
#endif
  long ret = 0;

  printk(KERN_INFO "%s: set_state %d\n", MODNAME, state);
  if ((ret = is_root_and_correct_password(password)) < 0)
    return ret;

  refmon.state = state;

  if (state == REFMON_STATE_ON)
    return probes_register();
  else if (state == REFMON_STATE_OFF)
    probes_unregister();

  return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_reference_monitor_set_state = (unsigned long)__x64_sys_reference_monitor_set_state;
#else
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _reference_monitor_add_path, const char *, password, const char *, path) {
#else
asmlinkage long sys_reference_monitor_add_path(const char *password, const char *path) {
#endif
  char *buffer = NULL;
  struct reference_monitor_path *node = NULL;
  long ret = 0;

  printk(KERN_INFO "%s: add_path\n", MODNAME);
  if ((ret = is_root_and_correct_password(password)) < 0)
    return ret;

  if (refmon.state != REFMON_STATE_REC_ON) {
    printk("%s: state does not allow to reconfigure\n", MODNAME);
    return -EPERM;
  }

  buffer = (char *)__get_free_page(GFP_ATOMIC);
  if (buffer == NULL) {
    printk("%s: error get_free_page in syscall add_path\n", MODNAME);
    ret = -ENOMEM;
    goto exit;
  }
  if (copy_from_user(buffer, path, PATH_MAX) < 0) {
    printk("%s: error copy_from_user (old_password) in syscall change_password\n", MODNAME);
    ret = -EINVAL;
    goto exit;
  }
  node = search_for_path_in_list(buffer);
  if (node != NULL) {
    printk("%s: syscall change_password node already in list\n", MODNAME);
    goto exit;
  }
  node = kmalloc(sizeof(*node), GFP_ATOMIC);
  if (node != NULL) {
    printk("%s: error kmalloc in syscall add_path\n", MODNAME);
    ret = -ENOMEM;
    goto exit;
  }
  node->path = buffer;

  spin_lock(&refmon.lock);
  list_add_rcu(&node->next, &refmon.list);
  spin_unlock(&refmon.lock);

exit:
  if (buffer)
    free_page((unsigned long)buffer);
  return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_reference_monitor_add_path = (unsigned long)__x64_sys_reference_monitor_add_path;
#else
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _reference_monitor_delete_path, const char *, password, const char *, path) {
#else
asmlinkage long sys_reference_monitor_delete_path(const char *password, const char *path) {
#endif
  char *buffer = NULL;
  struct reference_monitor_path *node = NULL;
  long ret = 0;

  printk(KERN_INFO "%s: delete_path\n", MODNAME);
  if ((ret = is_root_and_correct_password(password)) < 0)
    return ret;

  if (refmon.state != REFMON_STATE_REC_ON) {
    printk("%s: state does not allow to reconfigure\n", MODNAME);
    return -EPERM;
  }
  buffer = (char *)__get_free_page(GFP_ATOMIC);
  if (buffer == NULL) {
    printk("%s: error get_free_page in syscall add_path\n", MODNAME);
    ret = -ENOMEM;
    goto exit;
  }
  if (copy_from_user(buffer, path, PATH_MAX) < 0) {
    printk("%s: error copy_from_user (old_password) in syscall change_password\n", MODNAME);
    ret = -EINVAL;
    goto exit;
  }
  node = search_for_path_in_list(buffer);

  if (node) {
    spin_lock(&refmon.lock);
    list_del_rcu(&node->next);
    spin_unlock(&refmon.lock);
  }

exit:
  if (buffer)
    free_page((unsigned long)buffer);
  if (node)
    kfree(node);
  return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_reference_monitor_delete_path = (unsigned long)__x64_sys_reference_monitor_delete_path;
#else
#endif
