#ifndef REFERENCE_MONITOR_H
#define REFERENCE_MONITOR_H

#define FS_PATH "/tmp/sffs/mount/reference_monitor.log"

#ifdef __KERNEL__
#include <linux/spinlock_types.h>
#include <linux/types.h>

#define MODNAME "REFERENCE_MONITOR"
#define PASSWORD_MAX_LEN 128

struct reference_monitor_path {
  unsigned long i_ino;
  struct list_head next;
};

enum reference_monitor_state { RM_OFF, RM_ON, RM_REC_OFF, RM_REC_ON };

struct reference_monitor {
  enum reference_monitor_state state; // Reference Monitor State
  unsigned char *password_hash;       // Reference Monitor Password Hash
  spinlock_t lock;                    // Lock for write operations on RCU list (add/delete)
  struct list_head list;              // Paths to monitor, in a linked list
};

#endif // __KERNEL__
#endif // !REFERENCE_MONITOR_H
