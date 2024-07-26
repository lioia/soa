#ifndef UTILS_H
#define UTILS_H

#include <linux/dcache.h>
#include <linux/types.h>

#define SHA_LENGTH 32
#define READ_LENGTH 512

char *crypt_data(const unsigned char *data, bool is_file);
bool check_hash(const unsigned char *data, const unsigned char *hashed);
char *get_complete_path_from_dentry(struct dentry *dentry);
char *get_absolute_path_from_relative(char *path);
bool is_euid_root(void);
int is_root_and_correct_password(char *buffer, const char *password);
struct reference_monitor_path *search_for_path_in_list(const char *path);

#endif // !UTILS_H
