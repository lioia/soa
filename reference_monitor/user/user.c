#include <stdio.h>
#include <unistd.h>

#include "../reference_monitor.h"

#define CODE_1 174 // depends on the Kernel; TODO: get from module parameters file

int main(void) {
  printf("Hello, world\n");
  syscall(CODE_1, "test", REFMON_STATE_ON);
  return 0;
}
