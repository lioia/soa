#include "tasks.h"

#include <linux/slab.h>

void write_to_log(unsigned long data) {
  struct reference_monitor_packed_work *work = NULL;

  // Get the work
  work = container_of((void *)data, struct reference_monitor_packed_work, the_work);

  // TODO: write to file

  // Freeing work structure
  kfree(work->path);
  kfree(work);
}
