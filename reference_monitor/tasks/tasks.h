#ifndef TASKS_H
#define TASKS_H

#include <linux/workqueue.h>

struct reference_monitor_packed_work {
  pid_t tgid;                     // Program TGID
  pid_t tid;                      // Thread ID
  uid_t uid;                      // User ID
  uid_t euid;                     // Effective User ID
  char *program_path;             // Offending Program Path
  size_t program_path_len;        // Program Path Length
  char *primary_file_path;        // Offending File Path (primary)
  size_t primary_file_path_len;   // Primary File Path Length
  char *secondary_file_path;      // Offending File Path (secondary)
  size_t secondary_file_path_len; // Secondary File Path Length
  char *operation;                // Operation
  size_t operation_len;           // Operation Length
  struct work_struct the_work;    // `data`
};

void write_to_log(unsigned long data);

#endif // !TASKS_H
