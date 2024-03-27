#ifndef PASSWORD_H

#define SALT "reference_monitor_salt"

char *crypt_data(const unsigned char *data);
int check_hash(const unsigned char *data, const unsigned char *hashed);

#endif // !PASSWORD_H
