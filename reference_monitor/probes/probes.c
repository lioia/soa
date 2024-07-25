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

extern struct reference_monitor refmon;

// File create/edit
struct kretprobe vfs_open_probe;

// File delete
struct kretprobe security_path_unlink_probe;

// File link
/*struct kretprobe vfs_link_probe;*/

// Directory create
struct kretprobe security_path_mkdir_probe;

// Directory delete
struct kretprobe security_path_rmdir_probe;

// Directory edit (file move)
struct kretprobe security_path_rename_probe;

// Symbolic Link
/*struct kretprobe vfs_symlink_probe;*/

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
  HANDLE_PROBE(((struct path *)regs->di)->dentry, "open");
}

// int security_path_symlink(const struct path *dir, struct dentry *dentry, const char *old_name)
static int security_path_unlink_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  HANDLE_PROBE((struct dentry *)regs->si, "unlink");
}

/*static int vfs_link_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 1; }*/

// int security_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode)
static int security_path_mkdir_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  HANDLE_PROBE((struct dentry *)regs->si, "mkdir");
}

// int security_path_rmdir(const struct path *dir, struct dentry *dentry)
static int security_path_rmdir_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  HANDLE_PROBE((struct dentry *)regs->si, "rmdir");
}

// int security_path_rename(const struct path *old_dir, struct dentry *old_dentry,
//      const struct path *new_dir, struct dentry *new_dentry,
//      unsigned int flags)
static int security_path_rename_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  HANDLE_PROBE((struct dentry *)regs->si, "rename");
}

/*static int vfs_symlink_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 1; }*/

void probes_init(void) {
  CREATE_PROBE(vfs_open);
  CREATE_PROBE(security_path_unlink);
  /*CREATE_PROBE(vfs_link);*/
  CREATE_PROBE(security_path_mkdir);
  CREATE_PROBE(security_path_rmdir);
  CREATE_PROBE(security_path_rename);
  /*CREATE_PROBE(vfs_symlink);*/

  pr_info("%s: initialized probe\n", MODNAME);
}

int probes_register(void) {
  int ret = 0;

  REGISTER_PROBE(vfs_open);
  REGISTER_PROBE(security_path_unlink);
  /*REGISTER_PROBE(vfs_link);*/
  REGISTER_PROBE(security_path_mkdir);
  REGISTER_PROBE(security_path_rmdir);
  REGISTER_PROBE(security_path_rename);
  /*REGISTER_PROBE(vfs_symlink);*/
  pr_info("%s: correctly registered probes\n", MODNAME);
  return ret;
}

void probes_unregister(void) {
  unregister_kretprobe(&vfs_open_probe);
  unregister_kretprobe(&security_path_unlink_probe);
  /*unregister_kretprobe(&vfs_link_probe);*/
  unregister_kretprobe(&security_path_mkdir_probe);
  unregister_kretprobe(&security_path_rmdir_probe);
  unregister_kretprobe(&security_path_rename_probe);
  /*unregister_kretprobe(&vfs_symlink_probe);*/
  pr_info("%s: correctly unregistered probes\n", MODNAME);
}
