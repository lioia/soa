#include <linux/printk.h>
#include <linux/syscalls.h>
#include <linux/version.h>

#include "../probes/probes.h"
#include "../reference_monitor.h"

extern struct reference_monitor refmon;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _reference_monitor_change_password, const char *, password, const char *, old_password) {
#else
asmlinkage long sys_reference_monitor_change_password(const char *password, const char *old_password) {
#endif
  printk(KERN_INFO "%s: change_password %s\n", MODNAME, KERN_INFO);
  return 0;
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
  printk(KERN_INFO "%s: set_state %d\n", MODNAME, state);
  refmon.state = state;

  if (state == REFMON_STATE_ON)
    return probes_register();
  else if (state == REFMON_STATE_OFF)
    probes_unregister();

  return 0;
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
  printk(KERN_INFO "%s: add_path %s\n", MODNAME, KERN_INFO);
  return 0;
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
  printk(KERN_INFO "%s: delete_path %s\n", MODNAME, KERN_INFO);
  return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_reference_monitor_delete_path = (unsigned long)__x64_sys_reference_monitor_delete_path;
#else
#endif
