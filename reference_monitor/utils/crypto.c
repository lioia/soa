#include "crypto.h"

#include "linux/slab.h"
#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/printk.h>
#include <linux/string.h>

// Adapter from https://github.com/torvalds/linux/blob/master/Documentation/crypto/api-samples.rst

char *crypt_data(const unsigned char *data) {
  struct crypto_shash *alg = crypto_alloc_shash("sha256", 0, 0);
  if (IS_ERR(alg)) {
    printk(KERN_ERR "failed to allocate alg for sha256\n");
    return NULL;
  }
  int size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
  struct shash_desc *sdesc = kmalloc(size, GFP_KERNEL);
  if (sdesc == NULL) {
    crypto_free_shash(alg);
    printk(KERN_ERR "failed to allocate sdesc\n");
    return NULL;
  }
  sdesc->tfm = alg;

  char *digest = kmalloc(sizeof(*digest) * 32, GFP_KERNEL);
  if (digest == NULL) {
    crypto_free_shash(alg);
    kfree(sdesc);
    printk(KERN_ERR "failed to allocate digest\n");
    return NULL;
  }

  int ret = crypto_shash_digest(sdesc, data, strlen(data), digest);
  if (ret) {
    crypto_free_shash(alg);
    kfree(sdesc);
    kfree(digest);
    printk(KERN_ERR "failed to calculate digest\n");
    return NULL;
  }
  char *result = kmalloc(2 * 32 + 1, GFP_KERNEL);
  if (!result) {
    printk(KERN_ERR "failed to allocate result\n");
    return NULL;
  }
  for (int i = 0; i < 32; i++)
    sprintf(&result[i * 2], "%02x", digest[i]);

  crypto_free_shash(alg);
  kfree(sdesc);
  kfree(digest);
  return result;
}

int check_hash(const unsigned char *data, const unsigned char *hashed) {
  char *out = crypt_data(data);
  if (out == NULL) {
    printk(KERN_ERR "failed to crypt data\n");
    return -1;
  }
  return strcmp(out, hashed) == 0;
}
