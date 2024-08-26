#ifndef TASKS_H
#define TASKS_H

#include <linux/workqueue.h>

struct reference_monitor_packed_work {
  pid_t tgid;                  // Program TGID
  pid_t tid;                   // Thread ID
  uid_t uid;                   // User ID
  uid_t euid;                  // Effective User ID
  char *program_path;          // Offending Program Path
  char *primary_file_path;     // Offending File Path (primary)
  char *secondary_file_path;   // Offending File Path (secondary)
  char *operation;             // Operation
  struct work_struct the_work; // `data`
};

void write_to_log(unsigned long data);

#endif // !TASKS_H
