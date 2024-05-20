#ifndef REFERENCE_MONITOR_H
#define REFERENCE_MONITOR_H

#define REFMON_STATE_OFF 0b00
#define REFMON_STATE_ON 0b01
#define REFMON_STATE_REC_OFF 0b10
#define REFMON_STATE_REC_ON 0b11

// Only visible when compiling in kernel-space
#ifdef __KERNEL__
#include <linux/types.h>

#define MODNAME "REFERENCE_MONITOR"
#define PASSWORD_MAX_LEN 128

struct reference_monitor_path {
  char *path;
  struct list_head next;
};

struct reference_monitor {
  int state : 2;                // Using only 2 bits for the state (4 possible values)
  unsigned char *password_hash; // Reference Monitor Password Hash
  struct list_head list;        // Paths to monitor, in a linked list
};
#endif // !__KERNEL__

#endif // !REFERENCE_MONITOR_H
