#include <asm/current.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/workqueue.h>

#include "../tasks/tasks.h"
#include "../utils/utils.h"
#include "probes.h"

// TODO: add in kretprobe_instance data the filename trying to access
// TODO: add the filename to the work struct and log it

// File create/edit
struct kretprobe vfs_open_probe;

// File delete
struct kretprobe security_path_unlink_probe;

// File link
struct kretprobe security_inode_link_probe;

// Directory create
struct kretprobe security_path_mkdir_probe;

// Directory delete
struct kretprobe security_path_rmdir_probe;

// Directory edit (file move)
struct kretprobe security_path_rename_probe;

// Symbolic Link
struct kretprobe security_inode_symlink_probe;

// The post handler is executed only if the entry handler returns 0;
// it sets the return value of the syscall to an error value (EACCES) and it
// schedules the deferred work
static int probe_post_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  /*  struct reference_monitor_packed_work *work = NULL;*/
  /**/
  /*  // Get information about the offending program*/
  /*  work = kmalloc(sizeof(*work), GFP_ATOMIC);*/
  /*  if (work == NULL) {*/
  /*    pr_err("%s: kmalloc for reference_monitor_packed_work failed in probe_post_handler\n", MODNAME);*/
  /*    goto exit;*/
  /*  }*/
  /*  // Lock current thread*/
  /*  task_lock(current);*/
  /*  work->tgid = current->tgid;*/
  /*  work->tid = current->pid;*/
  /*  work->uid = __kuid_val(current->cred->uid);*/
  /*  work->euid = __kuid_val(current->cred->euid);*/
  /**/
  /*  // Get current pwd*/
  /*  work->path = get_path_from_dentry(current->mm->exe_file->f_path.dentry); // TODO: error checking*/
  /*  task_unlock(current);*/
  /**/
  /*  // Schedule deferred work*/
  /*  __INIT_WORK(&(work->the_work), (void *)write_to_log, (unsigned long)(&(work->the_work)));*/
  /**/
  /*  schedule_work(&work->the_work);*/
  /**/
  /*exit:*/
  // Set return value of the function to EACCES
  regs_set_return_value(regs, -EACCES);
  return 0;
}

// nt vfs_open(const struct path *, struct file *);
static int vfs_open_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct path *path = (struct path *)regs->di;
  struct file *file = (struct file *)regs->si;
  // If any of the writing flags are set, check the file
  if ((file->f_flags & O_WRONLY) || (file->f_flags & O_RDWR) || (file->f_flags & O_CREAT) ||
      (file->f_flags & O_APPEND) || (file->f_flags & O_TRUNC)) {
    return !is_dentry_protected(path->dentry);
  }

  // File opened in read mode
  return 1;
}

// int security_path_symlink(const struct path *dir, struct dentry *dentry, const char *old_name)
static int security_path_unlink_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct dentry *dentry = (struct dentry *)regs->si;
  return !is_dentry_protected(dentry);
}

// int security_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
static int security_inode_link_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct dentry *old_dentry = (struct dentry *)regs->di;
  struct dentry *new_dentry = (struct dentry *)regs->dx;
  bool old_protected = is_dentry_protected(old_dentry);
  bool new_protected = is_dentry_protected(new_dentry);

  return !(old_protected || new_protected);
}

// int security_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode)
static int security_path_mkdir_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct dentry *dentry = (struct dentry *)regs->si;
  return !is_dentry_protected(dentry);
}

// int security_path_rmdir(const struct path *dir, struct dentry *dentry)
static int security_path_rmdir_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct dentry *dentry = (struct dentry *)regs->si;
  return !is_dentry_protected(dentry);
}

// int security_path_rename(const struct path *old_dir, struct dentry *old_dentry,
//      const struct path *new_dir, struct dentry *new_dentry,
//      unsigned int flags)
static int security_path_rename_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct dentry *old_dentry = (struct dentry *)regs->si;
  struct dentry *new_dentry = (struct dentry *)regs->cx;
  bool old_protected = is_dentry_protected(old_dentry);
  bool new_protected = is_dentry_protected(new_dentry);

  return !(old_protected || new_protected);
}

// int security_inode_symlink(struct inode *dir, struct dentry *dentry, const char *old_name)
static int security_inode_symlink_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct dentry *new_dentry = (struct dentry *)regs->si;
  char *old_name = (char *)regs->dx;
  struct path old_path;
  bool old_protected = false, new_protected = false;

  if (kern_path(old_name, LOOKUP_FOLLOW, &old_path) == -ENOENT) {
    // Handling vi/emacs temp files
    if (kern_path(strcat(old_name, "~"), LOOKUP_FOLLOW, &old_path) != 0)
      return 0; // Path not found; nothing to do
  }

  old_protected = is_dentry_protected(old_path.dentry);
  new_protected = is_dentry_protected(new_dentry);

  path_put(&old_path);
  return !(old_protected || new_protected);
}

void probes_init(void) {
  CREATE_PROBE(vfs_open);
  CREATE_PROBE(security_path_unlink);
  CREATE_PROBE(security_inode_link);
  CREATE_PROBE(security_path_mkdir);
  CREATE_PROBE(security_path_rmdir);
  CREATE_PROBE(security_path_rename);
  CREATE_PROBE(security_inode_symlink);
}

int probes_register(void) {
  int ret = 0;

  REGISTER_PROBE(vfs_open);
  REGISTER_PROBE(security_path_unlink);
  REGISTER_PROBE(security_inode_link);
  REGISTER_PROBE(security_path_mkdir);
  REGISTER_PROBE(security_path_rmdir);
  REGISTER_PROBE(security_path_rename);
  REGISTER_PROBE(security_inode_symlink);
  return ret;
}

void probes_unregister(void) {
  unregister_kretprobe(&vfs_open_probe);
  unregister_kretprobe(&security_path_unlink_probe);
  unregister_kretprobe(&security_inode_link_probe);
  unregister_kretprobe(&security_path_mkdir_probe);
  unregister_kretprobe(&security_path_rmdir_probe);
  unregister_kretprobe(&security_path_rename_probe);
  unregister_kretprobe(&security_inode_symlink_probe);

  pr_info("%s: correctly unregistered probes\n", MODNAME);
}
