#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"

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
