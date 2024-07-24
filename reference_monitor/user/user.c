#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "io.h"
#include "user.h"

int main(int argc, char **argv) {
  int command = -1;
  int ret = 0;
  int hide = 0; // hide password
  if (argc == 2 && !strncmp(argv[1], "--hide", 4))
    hide = 1;
  while (1) {
    clear();

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
      ret = print_logs(hide);
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

int change_password(int hide) {
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

int set_state(int hide) {
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

int add_path(int hide) {
  char *password, *path;

  printf("Enter password: ");
  password = get_string(hide);
  printf("Enter path: ");
  path = get_string(0);

  return syscall(ADD_PATH, password, path);
}

int remove_path(int hide) {
  puts("NOT IMPLEMENTED YET");
  return 0;
}

int print_logs(int hide) {
  puts("NOT IMPLEMENTED YET");
  return 0;
}
