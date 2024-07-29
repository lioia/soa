#ifndef REFERENCE_MONITOR_H
#define REFERENCE_MONITOR_H

#include <linux/spinlock_types.h>
#include <linux/types.h>

#define MODNAME "REFERENCE_MONITOR"
#define PASSWORD_MAX_LEN 128
#define FS_PATH "/mnt/reference-monitor/fs.log"

struct reference_monitor_path {
  char *path;
  struct list_head next;
};

enum reference_monitor_state { RM_OFF, RM_ON, RM_REC_OFF, RM_REC_ON };

struct reference_monitor {
  enum reference_monitor_state state; // Reference Monitor State
  unsigned char *password_hash;       // Reference Monitor Password Hash
  spinlock_t lock;                    // Lock for write operations on RCU list (add/delete)
  struct list_head list;              // Paths to monitor, in a linked list
};

#endif // !REFERENCE_MONITOR_H
