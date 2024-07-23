#include <asm/ptrace.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "../reference_monitor.h"
#include "../utils/utils.h"
#include "probes.h"

// Macro for creating a probe from the function name
// do {} while(0) is needed to ensure that it runs as a single statement
#define CREATE_PROBE(func_name)                                                                                        \
  do {                                                                                                                 \
    func_name##_probe.kp.symbol_name = #func_name;                                                                     \
    func_name##_probe.entry_handler = (kretprobe_handler_t)func_name##_probe_entry_handler;                            \
    func_name##_probe.handler = (kretprobe_handler_t)probe_post_handler;                                               \
    func_name##_probe.maxactive = -1;                                                                                  \
  } while (0)

// Macro for registering a probe from the function name
#define REGISTER_PROBE(func_name)                                                                                      \
  do {                                                                                                                 \
    int ret;                                                                                                           \
    if ((ret = register_kretprobe(&func_name##_probe)) < 0) {                                                          \
      printk(KERN_ERR "%s: probe registration failed at %s: %d\n", MODNAME, #func_name, ret);                          \
      return ret;                                                                                                      \
    }                                                                                                                  \
  } while (0)

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
// so a single post handler can is used for all the probes,
// executed only if the probe has filtered the call
// it sets the return value of the syscall to an error value (EACCES)
static int probe_post_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  regs_set_return_value(regs, -EACCES);
  return 0;
}

// int vfs_open(const struct path *path, struct file *file)
static int vfs_open_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct path *di_path = (struct path *)regs->di;
  int ret = 0;
  // Get path from dentry
  char *path = get_complete_path_from_dentry(di_path->dentry);

  // Search for the path in the rcu list
  struct reference_monitor_path *entry = search_for_path_in_list(path);
  // No entry found, returning 1 so the post handler is not executed
  if (entry == NULL) {
    ret = 1;
    goto exit;
  }

  // TODO: deferred work (write to fs, calculate hash)

exit:
  if (path)
    kfree(path);
  return ret;
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
  CREATE_PROBE(vfs_open);
  CREATE_PROBE(vfs_unlink);
  CREATE_PROBE(vfs_link);
  CREATE_PROBE(vfs_mkdir);
  CREATE_PROBE(vfs_rmdir);
  CREATE_PROBE(vfs_rename);
  CREATE_PROBE(vfs_symlink);

  printk("%s: initialized probe\n", MODNAME);
}

int probes_register(void) {
  int ret = 0;

  REGISTER_PROBE(vfs_open);
  REGISTER_PROBE(vfs_unlink);
  REGISTER_PROBE(vfs_link);
  REGISTER_PROBE(vfs_mkdir);
  REGISTER_PROBE(vfs_rmdir);
  REGISTER_PROBE(vfs_rename);
  REGISTER_PROBE(vfs_symlink);
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
