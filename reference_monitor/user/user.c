#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../reference_monitor.h"

// TODO: get from module parameters file
#define CHANGE_PASSWORD 156
#define SET_STATE 174
#define ADD_PATH 177
#define DELETE_PATH 178

int main(void) {
  printf("Hello, world\n");
  long ret = syscall(CHANGE_PASSWORD, "password", "reference_monitor_default_password");
  if (ret < 0) {
    printf("syscall %d failed: %s\n", CHANGE_PASSWORD, strerror(errno));
    exit(EXIT_FAILURE);
  }
  puts("Correctly changed password");
  syscall(SET_STATE, "password", REFMON_STATE_ON);
  if (ret < 0) {
    printf("syscall %d failed: %s\n", SET_STATE, strerror(errno));
    exit(EXIT_FAILURE);
  }
  puts("Correctly activated reference monitor");
  exit(EXIT_SUCCESS);
}
