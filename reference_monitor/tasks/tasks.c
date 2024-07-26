#include "tasks.h"

#include <linux/printk.h>
#include <linux/slab.h>

#include "../reference_monitor.h"
#include "../utils/utils.h"

void write_to_log(unsigned long data) {
  struct reference_monitor_packed_work *work = NULL;
  char *hash = NULL;

  // Get the work
  work = container_of((void *)data, struct reference_monitor_packed_work, the_work);

  hash = crypt_data(work->path, true);
  pr_info("%s: log: %d %d %d %d %s %s\n", MODNAME, work->tgid, work->tid, work->uid, work->euid, work->path, hash);
  // TODO: write to file

  // Freeing work structure
  kfree(work->path);
  kfree(work);
}
