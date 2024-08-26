#include "linux/dcache.h"
#include "linux/printk.h"
#include "utils.h"

extern struct reference_monitor refmon;

char *get_path_from_dentry(struct dentry *dentry) {
  char *path = NULL, *buffer = NULL;

  buffer = kmalloc(sizeof(*buffer) * PATH_MAX, GFP_ATOMIC);
  if (buffer == NULL) {
    pr_info("%s: kmalloc failed in get_complete_path_from_dentry\n", MODNAME);
    return NULL;
  }

  path = dentry_path_raw(dentry, buffer, PATH_MAX);
  if (IS_ERR(path)) {
    pr_info("%s: dentry_path_raw failed in get_complete_path_from_dentry\n", MODNAME);
    path = NULL;
    goto exit;
  }

exit:
  if (buffer)
    kfree(buffer);
  return path;
}

// Search for path in the rcu list
struct reference_monitor_path *search_for_path_in_list(unsigned long i_ino) {
  struct reference_monitor_path *node = NULL, *ret = NULL;
  rcu_read_lock();
  list_for_each_entry_rcu(node, &refmon.list, next) {
    if (node->i_ino == i_ino) {
      ret = node;
      break;
    }
  }
  rcu_read_unlock();
  return ret;
}

// Returns true if dentry (or parent) is protected
bool is_file_or_parent_protected(struct dentry *dentry) {
  struct reference_monitor_path *node = NULL;

  // Searching current dentry
  if (d_is_negative(dentry))
    return false;

  node = search_for_path_in_list(dentry->d_inode->i_ino);
  if (node != NULL)
    return true;

  // Searching parent dentry
  if (d_is_negative(dentry->d_parent)) {
    pr_info("parent for %s is invalid", dentry->d_name.name);
    return false;
  }
  node = search_for_path_in_list(dentry->d_parent->d_inode->i_ino);
  if (node != NULL)
    return true;

  // dentry or parent not found
  return false;
}

struct dentry *get_dentry_from_pathname(char *path_name) {
  struct path path;
  struct dentry *dentry = NULL;

  // Expecting absolute path; so it has to start with /
  if (path_name[0] != '/') {
    pr_info("%s: path_name invalid in get_dentry_from_pathname\n", MODNAME);
    return NULL;
  }

  if (kern_path(path_name, LOOKUP_FOLLOW, &path) != 0) {
    pr_info("%s: kern_path failed in get_dentry_from_pathname\n", MODNAME);
    return NULL;
  }

  dentry = path.dentry;

  path_put(&path);
  return dentry;
}
