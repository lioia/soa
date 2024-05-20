#include <asm/ptrace.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/string.h>

#include "../reference_monitor.h"
#include "../utils/utils.h"
#include "probes.h"

extern struct reference_monitor refmon;

// File create/edit
struct kretprobe vfs_open_probe;

// File delete
struct kretprobe vfs_unlink_probe;

// File link
struct kretprobe vfs_link_probe;

// Directory create
struct kretprobe vfs_mkdir_probe;

// Directory delete
struct kretprobe vfs_rmdir_probe;

// Directory edit (file move)
struct kretprobe vfs_rename_probe;

// Symbolic Link
struct kretprobe vfs_symlink_probe;

// NOTE: the post handler is executed only if the entry handler returns 0
// so probably a single post handler can be used for all the probes,
// executed only if the probe has filtered the call; it should set the return
// value of the syscall to a error value (e.g. EACCES)
static int probe_post_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  regs_set_return_value(regs, -EACCES);
  return 0;
}

// int vfs_open(const struct path *path, struct file *file)
static int vfs_open_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct path *path = (struct path *)regs->di;
  // struct file *file = (struct file *)regs->si;

  char *complete_path = get_complete_path_from_dentry(path->dentry);
  struct reference_monitor_path *entry;
  rcu_read_lock();
  list_for_each_entry_rcu(entry, &refmon.list, next) {
    if (!strcmp(entry->path, complete_path)) {
      printk("%s: found entry in RCU\n", MODNAME);
      return 0;
    }
  }
  rcu_read_unlock();
  return 1;
}

static int vfs_unlink_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }

// int vfs_link(struct dentry *old_dentry, struct mnt_idmap *idmap,
// 	     struct inode *dir, struct dentry *new_dentry,
// 	     struct inode **delegated_inode)
static int vfs_link_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }

static int vfs_mkdir_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) { return 0; }

static int vfs_rmdir_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) { return 0; }

static int vfs_rename_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) { return 0; }

static int vfs_symlink_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) { return 0; }

void probes_init(void) {
  vfs_open_probe.kp.symbol_name = "vfs_open";
  vfs_open_probe.entry_handler = (kretprobe_handler_t)vfs_open_probe_entry_handler;
  vfs_open_probe.handler = (kretprobe_handler_t)probe_post_handler;
  vfs_open_probe.maxactive = -1;

  vfs_unlink_probe.kp.symbol_name = "vfs_unlink";
  vfs_unlink_probe.entry_handler = (kretprobe_handler_t)vfs_unlink_probe_entry_handler;
  vfs_unlink_probe.handler = (kretprobe_handler_t)probe_post_handler;
  vfs_unlink_probe.maxactive = -1;

  vfs_link_probe.kp.symbol_name = "vfs_link";
  vfs_link_probe.entry_handler = (kretprobe_handler_t)vfs_link_probe_entry_handler;
  vfs_link_probe.handler = (kretprobe_handler_t)probe_post_handler;
  vfs_link_probe.maxactive = -1;

  vfs_mkdir_probe.kp.symbol_name = "vfs_mkdir";
  vfs_mkdir_probe.entry_handler = (kretprobe_handler_t)vfs_mkdir_probe_entry_handler;
  vfs_mkdir_probe.handler = (kretprobe_handler_t)probe_post_handler;
  vfs_mkdir_probe.maxactive = -1;

  vfs_rmdir_probe.kp.symbol_name = "vfs_rmdir";
  vfs_rmdir_probe.entry_handler = (kretprobe_handler_t)vfs_rmdir_probe_entry_handler;
  vfs_rmdir_probe.handler = (kretprobe_handler_t)probe_post_handler;
  vfs_rmdir_probe.maxactive = -1;

  vfs_rename_probe.kp.symbol_name = "vfs_rename";
  vfs_rename_probe.entry_handler = (kretprobe_handler_t)vfs_rename_probe_entry_handler;
  vfs_rename_probe.handler = (kretprobe_handler_t)probe_post_handler;
  vfs_rename_probe.maxactive = -1;

  vfs_symlink_probe.kp.symbol_name = "vfs_symlink";
  vfs_symlink_probe.entry_handler = (kretprobe_handler_t)vfs_symlink_probe_entry_handler;
  vfs_symlink_probe.handler = (kretprobe_handler_t)probe_post_handler;
  vfs_symlink_probe.maxactive = -1;

  printk("%s: initialized probe\n", MODNAME);
}

int probes_register(void) {
  int ret = 0;

  if ((ret = register_kretprobe(&vfs_open_probe)) < 0) {
    printk("%s: probes registration failed at vfs_open: %d\n", MODNAME, ret);
    return ret;
  }
  if ((ret = register_kretprobe(&vfs_unlink_probe)) < 0) {
    printk("%s: probes registration failed at vfs_unlink: %d\n", MODNAME, ret);
    return ret;
  }
  if ((ret = register_kretprobe(&vfs_link_probe)) < 0) {
    printk("%s: probes registration failed at vfs_link: %d\n", MODNAME, ret);
    return ret;
  }
  if ((ret = register_kretprobe(&vfs_mkdir_probe)) < 0) {
    printk("%s: probes registration failed at vfs_mkdir: %d\n", MODNAME, ret);
    return ret;
  }
  if ((ret = register_kretprobe(&vfs_rmdir_probe)) < 0) {
    printk("%s: probes registration failed at vfs_rmdir: %d\n", MODNAME, ret);
    return ret;
  }
  if ((ret = register_kretprobe(&vfs_rename_probe)) < 0) {
    printk("%s: probes registration failed at vfs_rename: %d\n", MODNAME, ret);
    return ret;
  }
  if ((ret = register_kretprobe(&vfs_symlink_probe)) < 0) {
    printk("%s: probes registration failed at vfs_symlink: %d\n", MODNAME, ret);
    return ret;
  }
  printk("%s: correctly registered probes\n", MODNAME);
  return ret;
}

void probes_unregister(void) {
  unregister_kretprobe(&vfs_open_probe);
  unregister_kretprobe(&vfs_unlink_probe);
  unregister_kretprobe(&vfs_link_probe);
  unregister_kretprobe(&vfs_mkdir_probe);
  unregister_kretprobe(&vfs_rmdir_probe);
  unregister_kretprobe(&vfs_rename_probe);
  unregister_kretprobe(&vfs_symlink_probe);
  printk("%s: correctly unregistered probes\n", MODNAME);
}
