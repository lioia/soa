#ifndef UTILS_H
#define UTILS_H

#include <linux/dcache.h>
#include <linux/types.h>

char *get_complete_path_from_dentry(struct dentry *dentry);
bool is_euid_root(void);
int is_root_and_correct_password(const char *password);

#endif // !UTILS_H
