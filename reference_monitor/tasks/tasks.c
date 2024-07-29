#include "tasks.h"

#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/slab.h>

#include "../reference_monitor.h"
#include "../utils/utils.h"

void write_to_log(unsigned long data) {
  struct reference_monitor_packed_work *work = NULL;
  char *hash = NULL, *line = NULL;
  struct file *file = NULL;
  size_t len = 0;

  // Get the work
  work = container_of((void *)data, struct reference_monitor_packed_work, the_work);

  // Calculate hash of offending program contents
  hash = crypt_data(work->path, true);

  // Create output string
  len = snprintf(NULL, 0, "%d,%d,%u,%u,%s,%s\n", work->tgid, work->tid, work->uid, work->euid, work->path, hash);
  line = kmalloc(sizeof(*line) * len, GFP_ATOMIC);
  if (line == NULL) {
    pr_err("%s: kmalloc for line failed in write_to_log\n", MODNAME);
    pr_info("%s: %d,%d,%u,%u,%s,%s\n", MODNAME, work->tgid, work->tid, work->uid, work->euid, work->path, hash);
    goto exit;
  }
  sprintf(line, "%d,%d,%u,%u,%s,%s\n", work->tgid, work->tid, work->uid, work->euid, work->path, hash);

  // Open log file
  file = filp_open(FS_PATH, O_WRONLY, 0644);
  if (IS_ERR(file)) {
    pr_err("%s: filp_open failed in write_to_log (%ld)\n", MODNAME, PTR_ERR(file));
    pr_info("%s: %s\n", MODNAME, line);
    goto exit;
  }

  // Write to log file
  if (kernel_write(file, line, len, &file->f_pos) < 0) {
    pr_err("%s: kernel_write failed in write_to_log\n", MODNAME);
    pr_info("%s: %s\n", MODNAME, line);
    goto exit;
  }

exit:
  // Freeing work structure
  kfree(work->path);
  kfree(work);
  if (file && !IS_ERR(file))
    filp_close(file, NULL);
  if (line)
    kfree(line);
}
