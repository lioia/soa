#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../reference_monitor.h"

#define CODE_1 174 // depends on the Kernel; TODO: get from module parameters file

int main(void) {
  printf("Hello, world\n");
  long ret = syscall(156, 1, 2);
  if (ret < 0) {
    printf("syscall 156 failed: %s\n", strerror(errno));
  }
  syscall(CODE_1, "test", REFMON_STATE_ON);
  if (ret < 0) {
    printf("syscall %d failed: %s\n", CODE_1, strerror(errno));
  }
  return 0;
}
