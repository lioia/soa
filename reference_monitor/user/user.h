#ifndef USER_H
#define USER_H
#include <stdbool.h>

#define CHANGE_PASSWORD 156
#define SET_STATE 174
#define ADD_PATH 177
#define DELETE_PATH 178

int check_if_module_is_inserted();
int change_password(bool hide);
int set_state(bool hide);
int add_path(bool hide);
int remove_path(bool hide);
int print_logs();

#endif // !USER_H
