#include <crypto/hash.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
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
#include "utils.h"

extern struct reference_monitor refmon;

char *get_complete_path_from_dentry(struct dentry *dentry) {
  char *buffer = NULL, *raw = NULL, *path = NULL;
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
  bool ret;

  ret = uid_eq(current->cred->euid, GLOBAL_ROOT_UID);
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

// NOTE: look into getname in linux/fs.h
// FIXME: not working for ~
char *get_absolute_path_from_relative(char *rel_path) {
  struct path path;
  char *cleaned_path = NULL, *absolute_path = NULL, *result = NULL;
  int ret = 0;

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

// Adapted from https://github.com/torvalds/linux/blob/master/Documentation/crypto/api-samples.rst

char *crypt_data(const unsigned char *data, bool is_file) {
  // Variable Declaration
  int ret = 0, bytes_read = 0, i = 0;
  struct crypto_shash *tfm = NULL;
  struct shash_desc *desc = NULL;
  unsigned char digest[SHA_LENGTH];
  char *hash = NULL;
  struct file *file = NULL;
  loff_t pos = 0;
  char file_data[READ_LENGTH];

  tfm = crypto_alloc_shash("sha256", 0, 0);
  if (IS_ERR(tfm)) {
    pr_err("%s: crypto_alloc_shash failed in crypt_data\n", MODNAME);
    return NULL;
  }
  desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_ATOMIC);
  if (desc == NULL) {
    pr_err("%s: kmalloc failed for desc in crypt_data\n", MODNAME);
    goto exit;
  }
  desc->tfm = tfm;

  ret = crypto_shash_init(desc);
  if (ret < 0) {
    pr_err("%s: crypto_shash_init failed in crypt_data\n", MODNAME);
    goto exit;
  }

  if (is_file) {
    file = filp_open(data, O_RDONLY, 0);
    if (file == NULL || IS_ERR(file)) {
      pr_err("%s: filp_open failed for %s in crypt_data\n", MODNAME, data);
      goto exit;
    }

    while ((bytes_read = kernel_read(file, file_data, sizeof(*file_data) * READ_LENGTH, &pos)) > 0) {
      ret = crypto_shash_update(desc, file_data, bytes_read);
      if (ret < 0) {
        pr_err("%s: crypto_shash_update failed for file in crypt_data\n", MODNAME);
        goto exit;
      }
    }
  } else {
    ret = crypto_shash_update(desc, data, strlen(data));
    if (ret < 0) {
      pr_err("%s: crypto_shash_update failed for non file in crypt_data\n", MODNAME);
      goto exit;
    }
  }

  ret = crypto_shash_final(desc, digest);
  if (ret < 0) {
    pr_err("%s: crypto_shash_final failed in crypt_data\n", MODNAME);
    goto exit;
  }

  hash = kzalloc(sizeof(*hash) * 2 * SHA_LENGTH + 1, GFP_ATOMIC);
  if (hash == NULL) {
    pr_err("%s: kmalloc failed for hash in crypt_data\n", MODNAME);
    goto exit;
  }

  for (i = 0; i < SHA_LENGTH; i++)
    sprintf(&hash[i * 2], "%02x", digest[i]);

  hash[2 * SHA_LENGTH] = '\0';

exit:
  if (desc)
    kfree(desc);
  if (tfm)
    crypto_free_shash(tfm);
  if (file)
    filp_close(file, NULL);
  return hash;
}

bool check_hash(const unsigned char *data, const unsigned char *hashed) {
  // Variable Declaration
  char *out;

  out = crypt_data(data, false);
  if (out == NULL) {
    pr_err("%s: crypt_data failed\n", MODNAME);
    return -1;
  }
  return strcmp(out, hashed) == 0;
}
