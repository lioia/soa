#ifndef UTILS_H
#define UTILS_H

#include <linux/dcache.h>
#include <linux/types.h>

char *get_complete_path_from_dentry(struct dentry *dentry);
bool is_euid_root(void);
int is_root_and_correct_password(const char *password);
struct reference_monitor_path *search_for_path_in_list(const char *path);

#endif // !UTILS_H
