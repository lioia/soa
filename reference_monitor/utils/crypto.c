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
  struct crypto_shash *alg = NULL;
  struct shash_desc *sdesc = NULL;
  char *digest = NULL, *result = NULL;
  int size, ret, i;

  alg = crypto_alloc_shash("sha256", 0, 0);
  if (IS_ERR(alg)) {
    printk(KERN_ERR "failed to allocate alg for sha256\n");
    return NULL;
  }
  size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
  sdesc = kmalloc(size, GFP_KERNEL);
  if (sdesc == NULL) {
    printk(KERN_ERR "failed to allocate sdesc\n");
    goto exit;
  }
  sdesc->tfm = alg;

  digest = kmalloc(sizeof(*digest) * 32, GFP_KERNEL);
  if (digest == NULL) {
    printk(KERN_ERR "failed to allocate digest\n");
    goto exit;
  }

  ret = crypto_shash_digest(sdesc, data, strlen(data), digest);
  if (ret) {
    printk(KERN_ERR "failed to calculate digest\n");
    goto exit;
  }
  result = kmalloc(2 * 32 + 1, GFP_KERNEL);
  if (!result) {
    printk(KERN_ERR "failed to allocate result\n");
    goto exit;
  }
  for (i = 0; i < 32; i++)
    sprintf(&result[i * 2], "%02x", digest[i]);

exit:
  if (digest)
    kfree(digest);
  if (sdesc)
    kfree(sdesc);
  if (alg)
    crypto_free_shash(alg);
  return result;
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
