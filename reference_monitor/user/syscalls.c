#include "../reference_monitor.h"
#include "user.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int change_password(bool hide) {
  int ret = 0;
  char *old_password = NULL, *new_password = NULL;

  printf("Enter old password: ");
  old_password = get_string(hide);
  printf("Enter new password: ");
  new_password = get_string(hide);

  if (old_password == NULL || new_password == NULL)
    goto exit;

  ret = syscall(CHANGE_PASSWORD, new_password, old_password);

exit:
  if (new_password)
    free(new_password);
  if (old_password)
    free(old_password);
  return ret;
}

int set_state(bool hide) {
  int command = -1, ret = -1;
  char *password = NULL;

  printf("Enter password: ");
  password = get_string(hide);
  if (password == NULL)
    goto exit;

  while (1) {
    puts("Enter a possible state:");
    puts("1) OFF");
    puts("2) ON");
    puts("3) REC-OFF");
    puts("4) REC-ON");

    command = get_integer("Enter an option: ");
    if (command <= 0 || command > 4) {
      puts("Invalid option");
      continue;
    }

    break;
  }

  ret = syscall(SET_STATE, password, command - 1);

exit:
  if (password)
    free(password);

  return ret;
}

int add_path(bool hide) {
  int ret = -1;
  char *password = NULL, *path = NULL, *resolved_path = NULL;

  printf("Enter password: ");
  password = get_string(hide);
  printf("Enter path: ");
  path = get_string(false);
  if (password == NULL || path == NULL)
    goto exit;

  resolved_path = resolve_path(path);
  if (resolved_path == NULL)
    goto exit;

  ret = syscall(ADD_PATH, password, path);

exit:
  if (password)
    free(password);
  if (path)
    free(path);
  if (resolved_path)
    free(resolved_path);

  return ret;
}

int remove_path(bool hide) {
  int ret = -1;
  char *password = NULL, *path = NULL, *resolved_path = NULL;

  printf("Enter password: ");
  password = get_string(hide);
  printf("Enter path: ");
  path = get_string(false);
  if (password == NULL || path == NULL)
    goto exit;

  resolved_path = resolve_path(path);
  if (resolved_path == NULL)
    goto exit;

  ret = syscall(DELETE_PATH, password, resolved_path);

exit:
  if (password)
    free(password);
  if (path)
    free(path);
  if (resolved_path)
    free(resolved_path);

  return ret;
}

int print_logs() {
  int len = 0;
  char *cmd = NULL;

  // Check if file is present
  if (access(FS_PATH, R_OK) != 0) {
    fprintf(stderr, "Log is not mounted\n");
    return -1;
  }
  len = snprintf(NULL, 0, "cat %s", FS_PATH);
  cmd = malloc(sizeof(*cmd) * len);
  if (cmd == NULL) {
    perror("malloc failed in print_logs");
    return EXIT_FAILURE;
  }
  sprintf(cmd, "cat %s", FS_PATH);

  return system(cmd);
}
