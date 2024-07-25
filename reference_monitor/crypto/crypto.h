#ifndef CRYPTO_H
#define CRYPTO_H

#include <linux/types.h>

char *crypt_data(const unsigned char *data);
bool check_hash(const unsigned char *data, const unsigned char *hashed);

#endif // !CRYPTO_H
