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

#include "../crypto/crypto.h"
#include "../reference_monitor.h"
#include "utils.h"

extern struct reference_monitor refmon;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _reference_monitor_change_password, const char *, password, const char *, old_password) {
#else
asmlinkage long sys_reference_monitor_change_password(const char *password, const char *old_password) {
#endif
  char *buffer = NULL, *tmp = NULL;
  long ret = 0;

  pr_info("%s: change_password\n", MODNAME);
  // Get free page
  buffer = (char *)__get_free_page(GFP_ATOMIC);
  if (buffer == NULL) {
    pr_err("%s: get_free_page failed in syscall change_password\n", MODNAME);
    ret = -ENOMEM;
    goto exit;
  }

  // Check for root and if provided password (copy is inside the function) is correct
  if ((ret = is_root_and_correct_password(buffer, old_password)) < 0)
    goto exit;

  // Zero page for reusage
  clear_page(buffer);

  // Copy new password into a buffer
  if ((ret = copy_from_user(buffer, password, PASSWORD_MAX_LEN)) < 0) {
    pr_err("%s: cropy_from_user for password failed in syscall change_password\n", MODNAME);
    ret = -EINVAL;
    goto exit;
  }
  // Update the password hash
  tmp = crypt_data(buffer);
  if (tmp == NULL) {
    pr_err("crypt_data failed in change_password\n");
    ret = -EINVAL;
    goto exit;
  }
  kfree(refmon.password_hash);
  refmon.password_hash = tmp;

exit:
  if (buffer)
    free_page((unsigned long)buffer);
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
  char *buffer = NULL;
  int ret = 0;

  // Get free page
  buffer = (char *)__get_free_page(GFP_ATOMIC);
  if (buffer == NULL) {
    pr_err("%s: get_free_page failed in syscall change_password\n", MODNAME);
    ret = -ENOMEM;
    goto exit;
  }

  pr_info("%s: set_state %d\n", MODNAME, state);
  if ((ret = is_root_and_correct_password(buffer, password)) < 0)
    goto exit;

  // Update state
  // FIXME: adhere to specs for state change
  refmon.state = state;

exit:
  if (buffer)
    free_page((unsigned long)buffer);
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
  char *buffer = NULL, *absolute_path = NULL;
  struct reference_monitor_path *node = NULL;
  long ret = 0;

  pr_info(KERN_INFO "%s: add_path\n", MODNAME);
  // Get free page
  buffer = (char *)__get_free_page(GFP_ATOMIC);
  if (buffer == NULL) {
    pr_err("%s: get_free_page failed for buffer in syscall add_path\n", MODNAME);
    ret = -ENOMEM;
    goto exit;
  }
  // Check if root and provided password is correct
  if ((ret = is_root_and_correct_password(buffer, password)) < 0)
    return ret;

  // Check if it can be reconfigures
  if (refmon.state != RM_REC_ON && refmon.state != RM_REC_OFF) {
    pr_info("%s: state does not allow to reconfigure\n", MODNAME);
    return -EPERM;
  }

  // Copy provided path from user to buffer
  if ((ret = copy_from_user(buffer, path, PATH_MAX)) < 0) {
    pr_err("%s: copy_from_user for path failed in syscall add_path\n", MODNAME);
    ret = -EINVAL;
    goto exit;
  }

  // Setting the path to the buffer
  absolute_path = get_absolute_path_from_relative(buffer);
  if (absolute_path == NULL) {
    ret = -EINVAL;
    goto exit;
  }
  // Search for node in the rcu list
  node = search_for_path_in_list(absolute_path);
  // Node found, so the path is already in the list
  if (node != NULL) {
    pr_info("%s: path already in list in syscall add_path\n", MODNAME);
    goto exit;
  }
  // Node not found; creating new one
  node = kmalloc(sizeof(*node), GFP_ATOMIC);
  if (node == NULL) {
    pr_err("%s: kmalloc for node failed in syscall add_path\n", MODNAME);
    ret = -ENOMEM;
    goto exit;
  }
  node->path = absolute_path;

  // Adding the node in an atomic way to the rcu list
  spin_lock(&refmon.lock);
  list_add_rcu(&node->next, &refmon.list);
  spin_unlock(&refmon.lock);
  goto exit_no_free;

exit: // On error or node found
  if (buffer)
    free_page((unsigned long)buffer);
  if (absolute_path)
    kfree(absolute_path);
exit_no_free: // On correct insertion
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

  pr_info(KERN_INFO "%s: delete_path\n", MODNAME);
  // Get new buffer
  buffer = (char *)__get_free_page(GFP_ATOMIC);
  if (buffer == NULL) {
    pr_err("%s: get_free_page for buffer failed in syscall delete_path\n", MODNAME);
    ret = -ENOMEM;
    goto exit;
  }
  // Check if root and password provided is correct
  if ((ret = is_root_and_correct_password(buffer, password)) < 0)
    return ret;

  // Check if it can be reconfigured
  if (refmon.state != RM_REC_ON && refmon.state != RM_REC_OFF) {
    pr_info("%s: state does not allow to reconfigure\n", MODNAME);
    return -EPERM;
  }

  // Copy provided path into buffer
  if ((ret = copy_from_user(buffer, path, PATH_MAX)) < 0) {
    pr_err("%s: copy_from_user failed for path in syscall delete_path\n", MODNAME);
    ret = -EINVAL;
    goto exit;
  }
  // Search for node in the rcu list
  node = search_for_path_in_list(buffer);

  // If found, remove from the list
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
