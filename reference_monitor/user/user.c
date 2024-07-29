#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "io.h"
#include "user.h"

int main(int argc, char **argv) {
  // Check if module is loaded
  if (check_if_module_is_inserted() != 0)
    exit(EXIT_FAILURE);

  int command = -1;
  int ret = 0;
  bool hide = false; // hide password
  if (argc == 2 && !strncmp(argv[1], "--hide", 4))
    hide = true;

  while (1) {
    clear();

    // Print Menu
    puts("---REFERENCE MONITOR---");
    puts("1) Change Password");
    puts("2) Set State");
    puts("3) Add Path");
    puts("4) Remove Path");
    puts("5) Print Logs");
    puts("9) Quit");
    command = get_integer("Enter an option: ");
    switch (command) {
    case 1:
      ret = change_password(hide);
      break;
    case 2:
      ret = set_state(hide);
      break;
    case 3:
      ret = add_path(hide);
      break;
    case 4:
      ret = remove_path(hide);
      break;
    case 5:
      ret = print_logs();
      break;
    case 9:
      exit(EXIT_SUCCESS);
    default:
      puts("Invalid command");
      break;
    }
    if (ret < 0)
      perror("syscall failed");

    puts("Enter any key to continue");
    flush(stdin);
  }
  exit(EXIT_SUCCESS);
}

int check_if_module_is_inserted() {
  FILE *fp;
  char live[4];
  char *path = "/sys/module/the_reference_monitor/initstate";
  if (access(path, R_OK) != 0) {
    fprintf(stderr, "Module is not loaded\n");
    return -1;
  }
  fp = fopen(path, "r");
  if (fp == NULL) {
    fprintf(stderr, "Failed to read module initstate");
    return -1;
  }
  fread(live, sizeof(*live), 4, fp);
  return strncmp(live, "live", 4);
}

int change_password(bool hide) {
  char *old_password, *new_password;

  printf("Enter old password: ");
  old_password = get_string(hide);
  printf("Enter new password: ");
  new_password = get_string(hide);

  if (old_password == NULL || new_password == NULL) {
    perror("get_password failed in change_password\n");
  }

  return syscall(CHANGE_PASSWORD, new_password, old_password);
}

int set_state(bool hide) {
  int command = -1;
  char *password;

  printf("Enter password: ");
  password = get_string(hide);
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
  return syscall(SET_STATE, password, command - 1);
}

int add_path(bool hide) {
  char *password = NULL, *path = NULL;

  printf("Enter password: ");
  password = get_string(hide);
  printf("Enter path: ");
  path = get_string(false);

  return syscall(ADD_PATH, password, path);
}

int remove_path(bool hide) {
  char *password = NULL, *path = NULL;

  printf("Enter password: ");
  password = get_string(hide);
  printf("Enter path: ");
  path = get_string(false);

  return syscall(DELETE_PATH, password, path);
}

int print_logs() {
  char *path = "/tmp/reference_monitor/mount/reference_monitor.log";
  if (access(path, R_OK) != 0) {
    fprintf(stderr, "Log is not mounted\n");
    return -1;
  }
  return system("cat /tmp/reference_monitor/mount/reference_monitor.log");
}
