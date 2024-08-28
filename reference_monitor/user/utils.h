#ifndef UTILS
#define UTILS
#include <stdbool.h>

#define flush(stdin)                                                                                                   \
  do {                                                                                                                 \
    int c;                                                                                                             \
    while ((c = getchar()) != '\n' && c != EOF)                                                                        \
      ;                                                                                                                \
  } while (0)

#define clear() printf("\033[2J\033[H")

// Utils
int check_if_module_is_inserted();
char *resolve_path(char *path);

// Syscalls
int change_password(bool hide);
int set_state(bool hide);
int add_path(bool hide);
int remove_path(bool hide);
int print_logs();

// IO
int get_integer(char *prompt);
char *get_string(int hide);
#endif // !UTILS
