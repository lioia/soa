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

#include "utils.h"

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
  desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
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

  hash = kmalloc(sizeof(*hash) * 2 * SHA_LENGTH + 1, GFP_KERNEL);
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
  char *out = NULL;
  bool ret;

  out = crypt_data(data, false);
  if (out == NULL) {
    pr_err("%s: crypt_data failed\n", MODNAME);
    return -1;
  }
  ret = strcmp(out, hashed) == 0;

  kfree(out);

  return ret;
}
