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

// File edit
struct kretprobe vfs_open_probe;               // File Edit
struct kretprobe security_inode_create_probe;  // File Create
struct kretprobe security_path_unlink_probe;   // File Delete
struct kretprobe security_inode_link_probe;    // File Link
struct kretprobe security_path_mkdir_probe;    // Directory Create
struct kretprobe security_path_rmdir_probe;    // Directory Delete
struct kretprobe security_path_rename_probe;   // File/Directory Move
struct kretprobe security_inode_symlink_probe; // Symbolic Link

// The post handler is executed only if the entry handler returns 0;
// it sets the return value of the syscall to an error value (EACCES) and it
// schedules the deferred work
static int probe_post_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct reference_monitor_probe_data *data = (struct reference_monitor_probe_data *)p->data;
  struct reference_monitor_packed_work *work = kmalloc(sizeof(*work), GFP_KERNEL);
  if (work == NULL) {
    pr_err("%s: kmalloc for reference_monitor_packed_work failed in probe_post_handler\n", MODNAME);
    goto exit;
  }

  work->operation = data->operation;
  work->primary_file_path = data->primary_file_path;
  work->secondary_file_path = data->secondary_file_path;
  work->operation_len = data->operation_len;
  work->primary_file_path_len = data->primary_file_path_len;
  work->secondary_file_path_len = data->secondary_file_path_len;
  work->tgid = current->tgid;
  work->tid = current->pid;
  work->uid = __kuid_val(current->cred->uid);
  work->euid = __kuid_val(current->cred->euid);

  // Get current process
  work->program_path = get_pathname_from_path(&current->mm->exe_file->f_path, &work->program_path_len);
  if (work->program_path == NULL) {
    pr_info("%s: get_pathname_from_path failed in probe_post_handler (%lu)\n", MODNAME, work->program_path_len);
    goto exit_free;
  }

  // Schedule deferred work
  __INIT_WORK(&(work->the_work), (void *)write_to_log, (unsigned long)(&(work->the_work)));

  schedule_work(&work->the_work);
  goto exit;

exit_free:
  if (work)
    kfree(work);
exit:
  // Set return value of the function to EACCES
  regs_set_return_value(regs, -EACCES);
  return 0;
}

// int vfs_open(const struct path *, struct file *);
static int vfs_open_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct reference_monitor_probe_data *data = (struct reference_monitor_probe_data *)p->data;

  struct path *path = (struct path *)regs->di;
  struct file *file = (struct file *)regs->si;

  // File opened in read mode
  if (!(file->f_flags & O_WRONLY) && !(file->f_flags & O_RDWR) && !(file->f_flags & O_APPEND) &&
      !(file->f_flags & O_TRUNC) && !(file->f_flags & O_CREAT))
    return 1;

  // File opened in write mode
  if (is_file_or_parent_protected(path->dentry)) {
    if (fill_probe_data(data, "open", path->dentry, NULL) != 0)
      pr_err("%s: fill_probe_data failed in vfs_open_entry_handler\n", MODNAME);

    return 0;
  }

  return 1;
}

// int security_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode);
static int security_inode_create_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct reference_monitor_probe_data *data = (struct reference_monitor_probe_data *)p->data;
  struct inode *dir = (struct inode *)regs->di;
  struct dentry *dentry = (struct dentry *)regs->si;
  struct reference_monitor_path *node = search_for_path_in_list(dir->i_ino);
  if (node != NULL) {
    if (fill_probe_data(data, "create", dentry, NULL) != 0)
      pr_err("%s: fill_probe_data failed in security_inode_create_probe_entry_handler\n", MODNAME);

    return 0;
  }

  return 1;
}

// int security_path_unlink(const struct path *dir, struct dentry *dentry)
static int security_path_unlink_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct reference_monitor_probe_data *data = (struct reference_monitor_probe_data *)p->data;
  struct path *dir = (struct path *)regs->di;
  struct dentry *dentry = (struct dentry *)regs->si;

  bool dir_protected = is_file_or_parent_protected(dir->dentry);
  bool file_protected = is_file_or_parent_protected(dentry);

  if (dir_protected || file_protected) {
    if (fill_probe_data(data, "unlink", dentry, NULL) != 0)
      pr_err("%s: fill_probe_data failed in security_path_unlink_probe_entry_handler\n", MODNAME);

    return 0;
  }

  return 1;
}

// int security_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
static int security_inode_link_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct reference_monitor_probe_data *data = (struct reference_monitor_probe_data *)p->data;
  struct dentry *old_dentry = (struct dentry *)regs->di;
  struct dentry *new_dentry = (struct dentry *)regs->dx;
  bool old_protected = is_file_or_parent_protected(old_dentry);
  bool new_protected = is_file_or_parent_protected(new_dentry);

  if (old_protected || new_protected) {
    if (fill_probe_data(data, "link", old_dentry, new_dentry) != 0)
      pr_err("%s: fill_probe_data failed in security_inode_link_probe_entry_handler\n", MODNAME);

    return 0;
  }

  return 1;
}

// int security_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode)
static int security_path_mkdir_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct reference_monitor_probe_data *data = (struct reference_monitor_probe_data *)p->data;
  struct path *parent_path = (struct path *)regs->di;
  struct dentry *new_dentry = (struct dentry *)regs->si;

  bool parent_protected = is_file_or_parent_protected(parent_path->dentry);
  bool new_protected = is_file_or_parent_protected(new_dentry);

  if (parent_protected || new_protected) {
    if (fill_probe_data(data, "mkdir", new_dentry, NULL) != 0)
      pr_err("%s: fill_probe_data failed in security_path_mkdir_probe_entry_handler\n", MODNAME);

    return 0;
  }

  return 1;
}

// int security_path_rmdir(const struct path *dir, struct dentry *dentry)
static int security_path_rmdir_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct reference_monitor_probe_data *data = (struct reference_monitor_probe_data *)p->data;
  struct path *parent_path = (struct path *)regs->di;
  struct dentry *new_dentry = (struct dentry *)regs->si;

  bool parent_protected = is_file_or_parent_protected(parent_path->dentry);
  bool new_protected = is_file_or_parent_protected(new_dentry);

  if (parent_protected || new_protected) {
    if (fill_probe_data(data, "rmdir", new_dentry, NULL) != 0)
      pr_err("%s: fill_probe_data failed in security_path_rmdir_probe_entry_handler\n", MODNAME);

    return 0;
  }

  return 1;
}

// int security_path_rename(const struct path *old_dir, struct dentry *old_dentry,
//      const struct path *new_dir, struct dentry *new_dentry,
//      unsigned int flags)
static int security_path_rename_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct reference_monitor_probe_data *data = (struct reference_monitor_probe_data *)p->data;
  struct dentry *old_dentry = (struct dentry *)regs->si;
  struct dentry *new_dentry = (struct dentry *)regs->cx;
  bool old_protected = is_file_or_parent_protected(old_dentry);
  bool new_protected = is_file_or_parent_protected(new_dentry);

  if (old_protected || new_protected) {
    if (fill_probe_data(data, "rename", old_dentry, new_dentry) != 0)
      pr_err("%s: fill_probe_data failed in security_path_rename_probe_entry_handler\n", MODNAME);

    return 0;
  }

  return 1;
}

// int security_inode_symlink(struct inode *dir, struct dentry *dentry, const char *old_name)
static int security_inode_symlink_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
  struct reference_monitor_probe_data *data = (struct reference_monitor_probe_data *)p->data;
  struct dentry *new_dentry = (struct dentry *)regs->si;
  char *old_name = (char *)regs->dx;
  struct path old_path;
  bool old_protected = false, new_protected = false;

  if (kern_path(old_name, LOOKUP_FOLLOW, &old_path) == -ENOENT) {
    // Handling vi/emacs temp files
    if (kern_path(strcat(old_name, "~"), LOOKUP_FOLLOW, &old_path) != 0)
      return 1; // Path not found; nothing to do
  }

  old_protected = is_file_or_parent_protected(old_path.dentry);
  new_protected = is_file_or_parent_protected(new_dentry);

  if (old_protected || new_protected) {
    if (fill_probe_data(data, "symlink", new_dentry, NULL) != 0)
      pr_err("%s: fill_probe_data in security_inode_symlink_probe_entry_handler\n", MODNAME);

    path_put(&old_path);
    return 0;
  }

  path_put(&old_path);
  return 1;
}

int probes_init(void) {
  int ret = 0;

  CREATE_PROBE(vfs_open);
  CREATE_PROBE(security_inode_create);
  CREATE_PROBE(security_path_unlink);
  CREATE_PROBE(security_inode_link);
  CREATE_PROBE(security_path_mkdir);
  CREATE_PROBE(security_path_rmdir);
  CREATE_PROBE(security_path_rename);
  CREATE_PROBE(security_inode_symlink);

  REGISTER_PROBE(vfs_open);
  REGISTER_PROBE(security_inode_create);
  REGISTER_PROBE(security_path_unlink);
  REGISTER_PROBE(security_inode_link);
  REGISTER_PROBE(security_path_mkdir);
  REGISTER_PROBE(security_path_rmdir);
  REGISTER_PROBE(security_path_rename);
  REGISTER_PROBE(security_inode_symlink);
  return ret;
}

void probes_deinit(void) {
  unregister_kretprobe(&vfs_open_probe);
  unregister_kretprobe(&security_inode_create_probe);
  unregister_kretprobe(&security_path_unlink_probe);
  unregister_kretprobe(&security_inode_link_probe);
  unregister_kretprobe(&security_path_mkdir_probe);
  unregister_kretprobe(&security_path_rmdir_probe);
  unregister_kretprobe(&security_path_rename_probe);
  unregister_kretprobe(&security_inode_symlink_probe);

  pr_info("%s: correctly unregistered probes\n", MODNAME);
}

int probes_enable(void) {
  int ret = 0;

  ENABLE_PROBE(vfs_open);
  ENABLE_PROBE(security_inode_create);
  ENABLE_PROBE(security_path_unlink);
  ENABLE_PROBE(security_inode_link);
  ENABLE_PROBE(security_path_mkdir);
  ENABLE_PROBE(security_path_rmdir);
  ENABLE_PROBE(security_path_rename);
  ENABLE_PROBE(security_inode_symlink);
  return ret;
}

int probes_disable(void) {
  int ret = 0;

  DISABLE_PROBE(vfs_open);
  DISABLE_PROBE(security_inode_create);
  DISABLE_PROBE(security_path_unlink);
  DISABLE_PROBE(security_inode_link);
  DISABLE_PROBE(security_path_mkdir);
  DISABLE_PROBE(security_path_rmdir);
  DISABLE_PROBE(security_path_rename);
  DISABLE_PROBE(security_inode_symlink);
  return ret;
}

int fill_probe_data(struct reference_monitor_probe_data *data, char *operation, struct dentry *primary,
                    struct dentry *secondary) {
  data->operation = operation;
  data->operation_len = 7; // Max operation length (symlink)

  data->primary_file_path = get_pathname_from_dentry(primary, &data->primary_file_path_len);
  if (data->primary_file_path == NULL)
    return -1;

  if (secondary == NULL) {
    data->secondary_file_path = NULL;
    data->secondary_file_path_len = 0;
    return 0;
  }

  data->secondary_file_path = get_pathname_from_dentry(secondary, &data->secondary_file_path_len);
  if (data->secondary_file_path == NULL)
    return -1;

  return 0;
}
