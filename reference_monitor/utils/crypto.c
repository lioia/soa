#include "crypto.h"

#include "linux/slab.h"
#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/printk.h>
#include <linux/string.h>

// Adapted from https://github.com/torvalds/linux/blob/master/Documentation/crypto/api-samples.rst

char *crypt_data(const unsigned char *data) {
  // Variable Declaration
  struct crypto_shash *alg;
  int size, ret, i;
  struct shash_desc *sdesc;
  char *digest, *result;

  result = NULL;

  alg = crypto_alloc_shash("sha256", 0, 0);
  if (IS_ERR(alg)) {
    printk(KERN_ERR "failed to allocate alg for sha256\n");
    return NULL;
  }
  size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
  sdesc = kmalloc(size, GFP_KERNEL);
  if (sdesc == NULL) {
    printk(KERN_ERR "failed to allocate sdesc\n");
    goto free_alg;
  }
  sdesc->tfm = alg;

  digest = kmalloc(sizeof(*digest) * 32, GFP_KERNEL);
  if (digest == NULL) {
    printk(KERN_ERR "failed to allocate digest\n");
    goto free_sdesc_alg;
  }

  ret = crypto_shash_digest(sdesc, data, strlen(data), digest);
  if (ret) {
    printk(KERN_ERR "failed to calculate digest\n");
    goto free_all;
  }
  result = kmalloc(2 * 32 + 1, GFP_KERNEL);
  if (!result) {
    printk(KERN_ERR "failed to allocate result\n");
    goto free_all;
  }
  for (i = 0; i < 32; i++)
    sprintf(&result[i * 2], "%02x", digest[i]);

free_all:
  kfree(digest);
free_sdesc_alg:
  kfree(sdesc);
free_alg:
  crypto_free_shash(alg);
  return result;
}

int check_hash(const unsigned char *data, const unsigned char *hashed) {
  // Variable Declaration
  char *out;

  out = crypt_data(data);
  if (out == NULL) {
    printk(KERN_ERR "failed to crypt data\n");
    return -1;
  }
  return strcmp(out, hashed) == 0;
}
