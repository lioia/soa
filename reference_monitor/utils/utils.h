#ifndef UTILS_H
#define UTILS_H

#include <crypto/hash.h>
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
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>

#include "../reference_monitor.h"

#define SHA_LENGTH 32
#define READ_LENGTH 512

// Credentials
/**
 * @brief Checks if effective UID is root
 *
 * @return true if euid is root; false otherwise
 */
bool is_euid_root(void);

/**
 * @brief Checks if effective UID is root and if the provided password corresponds to the reference monitor password
 *
 * @param buffer temp buffer, pre allocated to copy data from; needs to be freed
 * @param password pointer to the user-space password string
 * @return 0 on success; any other number otherwise
 */
int is_root_and_correct_password(char *buffer, const char *password);

// Crypto
/**
 * @brief Calculate SHA256 hash of the provided data, or file
 *
 * @param data data to hash, or path of the file to hash
 * @param is_file how to treat data
 * @return SHA256 hash hex codes; needs to be freed
 */
char *crypt_data(const unsigned char *data, bool is_file);

/**
 * @brief Checks whether the provided hash is valid
 *
 * @param data to crypt
 * @param hashed what to check against
 * @return true on success; false otherwise
 */
bool check_hash(const unsigned char *data, const unsigned char *hashed);

// dentry and paths
/**
 * @brief Searches for a inode number inside the RCU list
 *
 * @param i_ino inode number to search
 * @return reference to the node in the RCU list if found; NULL othwerise
 */
struct reference_monitor_path *search_for_path_in_list(unsigned long i_ino);

/**
 * @brief Checks if the provided file (identified by dentry) or its parent is protected
 *
 * @param dentry file to search
 * @return true on success; false othwerise
 */
bool is_file_or_parent_protected(struct dentry *dentry);

/**
 * @brief Get corresponding dentry from a path
 *
 * @param path_name file path
 * @return dentry of path_name
 */
struct dentry *get_dentry_from_pathname(char *path_name);

/**
 * @brief Returns the pathname from a dentry
 *
 * @param dentry the file
 * @param len pointer to a size_t, length of the path will be saved here
 * @return pathname of the dentry
 */
char *get_pathname_from_dentry(struct dentry *dentry, size_t *len);

/**
 * @brief Returns the pathname from a path
 *
 * @param path the file
 * @param len pointer to a size_t, length of the path will be saved here
 * @return pathname of the path
 */
char *get_pathname_from_path(struct path *path, size_t *len);

#endif // !UTILS_H
