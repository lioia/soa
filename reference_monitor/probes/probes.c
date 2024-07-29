#include <asm/current.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
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

#include "../reference_monitor.h"
#include "../tasks/tasks.h"
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

// The post handler is executed only if the entry handler returns 0;
// it sets the return value of the syscall to an error value (EACCES) and it
// schedules the deferred work
static int probe_post_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct reference_monitor_packed_work *work = NULL;
  struct dentry *dentry = NULL;

  // Set return value of the function to EACCES
  regs_set_return_value(regs, -EACCES);

  // Get information about the offending program
  work = kmalloc(sizeof(*work), GFP_ATOMIC);
  if (work == NULL) {
    pr_err("%s: kmalloc for reference_monitor_packed_work failed in probe_post_handler\n", MODNAME);
    goto exit;
  }
  // Lock current thread
  task_lock(current);
  work->tgid = current->tgid;
  work->tid = current->pid;
  work->uid = __kuid_val(current->cred->uid);
  work->euid = __kuid_val(current->cred->euid);

  // Get current pwd
  dentry = current->mm->exe_file->f_path.dentry;
  work->path = get_complete_path_from_dentry(dentry);
  task_unlock(current);

  // Schedule deferred work
  __INIT_WORK(&(work->the_work), (void *)write_to_log, (unsigned long)(&(work->the_work)));

  schedule_work(&work->the_work);

exit:
  return 0;
}

// int vfs_open(const struct path *path, struct file *file)
static int vfs_open_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  HANDLE_PROBE(((struct path *)regs->di)->dentry);
}

// int security_path_symlink(const struct path *dir, struct dentry *dentry, const char *old_name)
static int security_path_unlink_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  HANDLE_PROBE((struct dentry *)regs->si);
}

/*static int vfs_link_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 1; }*/

// int security_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode)
static int security_path_mkdir_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  HANDLE_PROBE((struct dentry *)regs->si);
}

// int security_path_rmdir(const struct path *dir, struct dentry *dentry)
static int security_path_rmdir_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  HANDLE_PROBE((struct dentry *)regs->si);
}

// int security_path_rename(const struct path *old_dir, struct dentry *old_dentry,
//      const struct path *new_dir, struct dentry *new_dentry,
//      unsigned int flags)
static int security_path_rename_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  HANDLE_PROBE((struct dentry *)regs->si);
}

/*static int vfs_symlink_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 1; }*/

int probes_init(void) {
  int ret = 0;

  CREATE_PROBE(vfs_open);
  CREATE_PROBE(security_path_unlink);
  /*CREATE_PROBE(vfs_link);*/
  CREATE_PROBE(security_path_mkdir);
  CREATE_PROBE(security_path_rmdir);
  CREATE_PROBE(security_path_rename);
  /*CREATE_PROBE(vfs_symlink);*/

  REGISTER_PROBE(vfs_open);
  REGISTER_PROBE(security_path_unlink);
  /*REGISTER_PROBE(vfs_link);*/
  REGISTER_PROBE(security_path_mkdir);
  REGISTER_PROBE(security_path_rmdir);
  REGISTER_PROBE(security_path_rename);
  /*REGISTER_PROBE(vfs_symlink);*/
  return ret;
}

void probes_deinit(void) {
  unregister_kretprobe(&vfs_open_probe);
  unregister_kretprobe(&security_path_unlink_probe);
  /*unregister_kretprobe(&vfs_link_probe);*/
  unregister_kretprobe(&security_path_mkdir_probe);
  unregister_kretprobe(&security_path_rmdir_probe);
  unregister_kretprobe(&security_path_rename_probe);
  /*unregister_kretprobe(&vfs_symlink_probe);*/
  pr_info("%s: correctly unregistered probes\n", MODNAME);
}
