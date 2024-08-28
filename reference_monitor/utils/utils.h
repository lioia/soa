#ifndef UTILS_H
#define UTILS_H

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

#define SHA_LENGTH 32
#define READ_LENGTH 512

// Credentials
bool is_euid_root(void);
int is_root_and_correct_password(char *buffer, const char *password);

// Crypto
char *crypt_data(const unsigned char *data, bool is_file);
bool check_hash(const unsigned char *data, const unsigned char *hashed);

// dentry and paths
struct dentry *get_dentry_from_pathname(char *path_name);
struct reference_monitor_path *search_for_path_in_list(unsigned long i_ino);
bool is_file_or_parent_protected(struct dentry *dentry);
char *get_pathname_from_dentry(struct dentry *dentry, size_t *len);
char *get_pathname_from_path(struct path *path, size_t *len);

#endif // !UTILS_H
