#include "utils.h"

extern struct reference_monitor refmon;

// Check if effective user id is root
bool is_euid_root(void) {
  bool ret = uid_eq(current->cred->euid, GLOBAL_ROOT_UID);
  if (!ret)
    pr_info("%s: user is not euid root\n", MODNAME);

  return ret;
}

int is_root_and_correct_password(char *buffer, const char *password) {
  int ret = 0;

  // Check if root
  if (!is_euid_root())
    return -EPERM;

  // Copy provided password from user into buffer
  if ((ret = copy_from_user(buffer, password, PASSWORD_MAX_LEN)) < 0) {
    pr_err("%s: copy_from_user for password failed in is_root_and_correct_password\n", MODNAME);
    ret = -EINVAL;
    goto exit;
  }

  // Check if the hash differs
  if (!check_hash(buffer, refmon.password_hash)) {
    pr_err("%s: check_hash failed in is_root_and_correct_password\n", MODNAME);
    ret = -EPERM;
  }
exit:
  return ret;
}
