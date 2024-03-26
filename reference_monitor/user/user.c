#include <stdio.h>
#include <unistd.h>

#define CODE_1 156 // depends on the Kernel; TODO: get from module parameters file

int main(void) {
  printf("Hello, world\n");
  syscall(CODE_1);
  return 0;
}
