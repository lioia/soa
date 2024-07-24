#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/limits.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include "../reference_monitor.h"
#include "crypto.h"
#include "utils.h"

extern struct reference_monitor refmon;

char *get_complete_path_from_dentry(struct dentry *dentry) {
  char *buffer, *raw = NULL, *path;
  int len = 0;

  // Allocate buffer as a page (PATH_MAX is 4096)
  buffer = (char *)__get_free_page(GFP_ATOMIC);
  if (buffer == NULL) {
    pr_err("%s: get_free_page failed for buffer in get_complete_path_from_dentry\n", MODNAME);
    return NULL;
  }

  // Get complete path in ret (ret is the starting point in buf of the path)
  raw = dentry_path_raw(dentry, buffer, PATH_MAX);
  if (IS_ERR(raw)) {
    pr_err("%s: dentry_path_raw failed in get_complete_path_from_dentry (%ld)\n", MODNAME, PTR_ERR(raw));
    goto exit;
  }
  // Allocate buffer for this path
  len = strlen(raw) + 1;
  path = (char *)kmalloc(sizeof(*path) * len, GFP_ATOMIC);
  if (path == NULL) {
    pr_err("%s kmalloc for path failed in get_complete_path_from_dentry\n", MODNAME);
    goto exit;
  }
  // Copy the string from the buffer to path
  strncpy(path, raw, len - 1);
  path[len] = '\0';
exit:
  if (buffer)
    free_page((unsigned long)buffer);
  // NOTE: freeing ret should not be necessary as it is just a pointer to memory allocated in buf
  return path;
}

// Check if effective user id is root
bool is_euid_root(void) {
  const struct cred *cur_cred;
  bool ret;

  cur_cred = current_cred();
  ret = uid_eq(cur_cred->euid, GLOBAL_ROOT_UID);
  if (!ret)
    pr_info("%s: user is not euid root\n", MODNAME);

  return ret;
}

int is_root_and_correct_password(char *buffer, const char *password) {
  int ret = 0;

  // Check if root
  if (!is_euid_root())
    return -EPERM;

  // Copy provided password from user into buffer
  if ((ret = copy_from_user(buffer, password, PASSWORD_MAX_LEN)) < 0) {
    pr_err("%s: copy_from_user for password failed in is_root_and_correct_password\n", MODNAME);
    ret = -EINVAL;
    goto exit;
  }

  // Check if the hash differs
  if (!check_hash(buffer, refmon.password_hash)) {
    pr_err("%s: check_hash failed in is_root_and_correct_password\n", MODNAME);
    ret = -EPERM;
    goto exit;
  }
exit:
  return ret;
}

// Search for path in the rcu list
struct reference_monitor_path *search_for_path_in_list(const char *path) {
  bool found = false;
  struct reference_monitor_path *node = NULL;
  rcu_read_lock();
  list_for_each_entry_rcu(node, &refmon.list, next) {
    if (!strcmp(node->path, path)) {
      found = true;
      break;
    }
  }
  rcu_read_unlock();
  return found ? node : NULL;
}

// FIXME: not working for ~
char *get_absolute_path_from_relative(char *rel_path) {
  struct path path;
  char *cleaned_path, *absolute_path, *result = NULL;
  int ret;

  if (rel_path[0] == '~')
    cleaned_path = kstrdup(rel_path + 1, GFP_ATOMIC);
  else
    cleaned_path = kstrdup(rel_path, GFP_ATOMIC);
  if (cleaned_path == NULL) {
    pr_err("%s: kstrdup failed in get_absolute_path_from_relative\n", MODNAME);
    return NULL;
  }

  // Follow relative path
  ret = kern_path(cleaned_path, LOOKUP_FOLLOW, &path);
  if (ret) {
    pr_err("%s: kern_path failed in get_absolute_path_from_relative\n", MODNAME);
    kfree(cleaned_path);
    return NULL;
  }

  // Allocate space for the absolute path
  absolute_path = kmalloc(sizeof(*absolute_path) * PATH_MAX, GFP_ATOMIC);
  if (absolute_path == NULL) {
    pr_err("%s: kmalloc for absolute_path failed in get_absolute_path_from_relative\n", MODNAME);
    goto exit;
  }

  // Convert path into string
  result = d_path(&path, absolute_path, PATH_MAX);
  if (IS_ERR(result)) {
    pr_err("%s: d_path failed in get_absolute_path_from_relative\n", MODNAME);
    kfree(absolute_path);
    result = NULL;
  }

exit:
  path_put(&path);
  kfree(cleaned_path);
  return result;
}
