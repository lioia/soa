#include "crypto.h"

#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

// Adapted from https://github.com/torvalds/linux/blob/master/Documentation/crypto/api-samples.rst

char *crypt_data(const unsigned char *data) {
  // Variable Declaration
  struct crypto_shash *tfm = NULL;
  struct shash_desc *desc = NULL;
  char *digest = NULL;
  int ret;

  tfm = crypto_alloc_shash("sha256", 0, 0);
  if (IS_ERR(tfm)) {
    pr_err("crypto_alloc_shash failed\n");
    return NULL;
  }
  desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
  if (desc == NULL) {
    pr_err("kmalloc failed for desc\n");
    goto exit;
  }
  desc->tfm = tfm;

  ret = crypto_shash_init(desc);
  if (ret < 0) {
    pr_err("crypto_shash_init failed\n");
    goto exit;
  }

  ret = crypto_shash_update(desc, data, strlen(data));
  if (ret < 0) {
    pr_err("crypto_shash_update failed\n");
    goto exit;
  }

  digest = kmalloc(sizeof(*digest) * 32, GFP_KERNEL);
  if (digest == NULL) {
    pr_err("kmalloc failed for buffer\n");
    goto exit;
  }

  ret = crypto_shash_final(desc, digest);
  if (ret < 0) {
    pr_err("crypto_shash_final failed\n");
    goto exit;
  }

exit:
  if (desc)
    kfree(desc);
  if (tfm)
    crypto_free_shash(tfm);
  return digest;
}

bool check_hash(const unsigned char *data, const unsigned char *hashed) {
  // Variable Declaration
  char *out;

  out = crypt_data(data);
  if (out == NULL) {
    printk(KERN_ERR "failed to crypt data\n");
    return -1;
  }
  return strcmp(out, hashed) == 0;
}
