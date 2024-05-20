#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/limits.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include "../reference_monitor.h"
#include "crypto.h"
#include "utils.h"

extern struct reference_monitor refmon;

char *get_complete_path_from_dentry(struct dentry *dentry) {
  char *buf, *path;

  // Allocate buffer as a page (PATH_MAX is 4096)
  buf = (char *)__get_free_page(GFP_ATOMIC);
  if (buf == NULL) {
    printk("%s: error calling get_free_page in dentry_complete_path\n", MODNAME);
    return NULL;
  }

  // Get complete path in ret (ret is the starting point in buf of the path)
  path = dentry_path_raw(dentry, buf, PATH_MAX);
  if (IS_ERR(path)) {
    printk("%s error calling dentry_path_raw in dentry_complete_path (%ld)\n", MODNAME, PTR_ERR(path));
    goto exit;
  }
exit:
  free_page((unsigned long)buf);
  return path;
}

bool is_euid_root(void) {
  const struct cred *cur_cred;

  cur_cred = current_cred();
  bool ret = uid_eq(cur_cred->euid, GLOBAL_ROOT_UID);
  if (!ret)
    printk("%s: user is not effective uid root\n", MODNAME);

  return ret;
}

int is_root_and_correct_password(const char *password) {
  char *buffer = NULL;
  int ret = 0;

  if (!is_euid_root())
    return -EPERM;

  buffer = kmalloc(sizeof(*buffer) * PASSWORD_MAX_LEN, GFP_ATOMIC);
  if (buffer == NULL) {
    printk("%s: error kmalloc in syscall change_password\n", MODNAME);
    ret = -ENOMEM;
    goto exit;
  }

  if (copy_from_user(buffer, password, PASSWORD_MAX_LEN) < 0) {
    printk("%s: error copy_from_user (old_password) in syscall change_password\n", MODNAME);
    ret = -EINVAL;
    goto exit;
  }

  if (!check_hash(buffer, refmon.password_hash)) {
    printk("%s: check_hash failed in syscall change_password", MODNAME);
    ret = -EPERM;
    goto exit;
  }
exit:
  if (buffer)
    kfree(buffer);
  return ret;
}
