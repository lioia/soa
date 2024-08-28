#include "utils.h"

extern struct reference_monitor refmon;

// Search for path in the rcu list
struct reference_monitor_path *search_for_path_in_list(unsigned long i_ino) {
  struct reference_monitor_path *node = NULL, *ret = NULL;
  rcu_read_lock();
  list_for_each_entry_rcu(node, &refmon.list, next) {
    if (node->i_ino == i_ino) {
      ret = node;
      break;
    }
  }
  rcu_read_unlock();
  return ret;
}

// Returns true if dentry (or parent) is protected
bool is_file_or_parent_protected(struct dentry *dentry) {
  struct reference_monitor_path *node = NULL;

  // Searching current dentry
  if (d_is_negative(dentry))
    return false;

  node = search_for_path_in_list(dentry->d_inode->i_ino);
  if (node != NULL)
    return true;

  // Searching parent dentry
  if (d_is_negative(dentry->d_parent)) {
    pr_info("parent for %s is invalid", dentry->d_name.name);
    return false;
  }
  node = search_for_path_in_list(dentry->d_parent->d_inode->i_ino);
  if (node != NULL)
    return true;

  // dentry or parent not found
  return false;
}

struct dentry *get_dentry_from_pathname(char *path_name) {
  struct path path;
  struct dentry *dentry = NULL;

  // Expecting absolute path; so it has to start with /
  if (path_name[0] != '/') {
    pr_info("%s: path_name invalid in get_dentry_from_pathname\n", MODNAME);
    return NULL;
  }

  if (kern_path(path_name, LOOKUP_FOLLOW, &path) != 0) {
    pr_info("%s: kern_path failed in get_dentry_from_pathname\n", MODNAME);
    return NULL;
  }

  dentry = path.dentry;

  path_put(&path);
  return dentry;
}

#define GET_PATHNAME(func, ptr, path_ptr, len_ptr)                                                                     \
  do {                                                                                                                 \
    char *pathname = NULL, *buffer = NULL;                                                                             \
    /* Allocate a buffer of PATH_MAX, to use in func */                                                                \
    buffer = kzalloc(sizeof(*buffer) * PATH_MAX, GFP_KERNEL);                                                          \
    if (buffer == NULL) {                                                                                              \
      pr_err("%s: kmalloc failed in GET_PATHNAME using %s\n", MODNAME, #func);                                         \
      goto exit;                                                                                                       \
    }                                                                                                                  \
                                                                                                                       \
    /* Call either d_path or dentry_path_raw */                                                                        \
    pathname = func(ptr, buffer, PATH_MAX);                                                                            \
    if (IS_ERR(pathname)) {                                                                                            \
      pr_err("%s: dentry_path_raw failed in GET_PATHNAME using %s\n", MODNAME, #func);                                 \
      goto exit;                                                                                                       \
    }                                                                                                                  \
                                                                                                                       \
    /* Store length of the path */                                                                                     \
    *len_ptr = strlen(pathname) + 1;                                                                                   \
                                                                                                                       \
    /* Allocate a new path, to return to the caller */                                                                 \
    path_ptr = kzalloc(sizeof(*path_ptr) * *len_ptr, GFP_KERNEL);                                                      \
    if (path_ptr == NULL) {                                                                                            \
      pr_err("%s: kmalloc failed in GET_PATHNAME using %s\n", MODNAME, #func);                                         \
      *len_ptr = 0;                                                                                                    \
      goto exit;                                                                                                       \
    }                                                                                                                  \
                                                                                                                       \
    /* Copy the result from func into the new path */                                                                  \
    strscpy(path_ptr, pathname, *len_ptr);                                                                             \
                                                                                                                       \
  exit:                                                                                                                \
    /* Free buffer (pathname is a pointer inside buffer, so it does not need to be freed) */                           \
    if (buffer)                                                                                                        \
      kfree(buffer);                                                                                                   \
    /* Return path is allocated but the length of the path is 0, so it needs to be freed */                            \
    if (*len_ptr == 0 && path_ptr) {                                                                                   \
      kfree(path_ptr);                                                                                                 \
      path_ptr = NULL;                                                                                                 \
    }                                                                                                                  \
  } while (0)

char *get_pathname_from_dentry(struct dentry *dentry, size_t *len) {
  char *result = NULL;
  GET_PATHNAME(dentry_path_raw, dentry, result, len);
  return result;
}

char *get_pathname_from_path(struct path *path, size_t *len) {
  char *result = NULL;
  GET_PATHNAME(d_path, path, result, len);
  return result;
}
