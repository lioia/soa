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
  char *primary_file_path = NULL, *secondary_file_path;
  size_t len = 0;

  // Get the work
  work = container_of((void *)data, struct reference_monitor_packed_work, the_work);

  primary_file_path = work->primary_file_path == NULL ? "" : work->primary_file_path;
  secondary_file_path = work->secondary_file_path == NULL ? "" : work->secondary_file_path;

  // Calculate hash of offending program contents
  hash = crypt_data(work->program_path, true);
  if (hash == NULL) {
    pr_err("%s: crypt_data failed in write_to_log\n", MODNAME);
    pr_info("%s-log: Operation: %s; TGID: %d; TID: %d; UID: %u; EUID: %u\nPrimary File Path: %s; Secondary File Path: "
            "%s\nProgram Path: %s\n\n",
            MODNAME, work->operation, work->tgid, work->tid, work->uid, work->euid, primary_file_path,
            secondary_file_path, work->program_path);
    goto exit;
  }

  // Create output string
  len = snprintf(NULL, 0, "%s,%d,%d,%d,%d,%s,%s,%s,%s", work->operation, work->tgid, work->tid, work->uid, work->euid,
                 primary_file_path, secondary_file_path, work->program_path, hash);

  line = kmalloc(sizeof(*line) * len, GFP_ATOMIC);
  if (line == NULL) {
    pr_err("%s: kmalloc for line failed in write_to_log\n", MODNAME);
    pr_info("%s-log: Operation: %s; TGID: %d; TID: %d; UID: %u; EUID: %u\nPrimary File Path: %s; Secondary File Path: "
            "%s\nProgram Path: %s\nProgram Hash: %s\n\n",
            MODNAME, work->operation, work->tgid, work->tid, work->uid, work->euid, primary_file_path,
            secondary_file_path, work->program_path, hash);
    goto exit;
  }
  sprintf(line, "%s,%d,%d,%d,%d,%s,%s,%s,%s", work->operation, work->tgid, work->tid, work->uid, work->euid,
          primary_file_path, secondary_file_path, work->program_path, hash);

  // Open log file
  file = filp_open(FS_PATH, O_WRONLY, 0644);
  if (IS_ERR(file)) {
    pr_err("%s: filp_open failed in write_to_log (%ld)\n", MODNAME, PTR_ERR(file));
    pr_info("%s-log: %s\n", MODNAME, line);
    goto exit;
  }

  // Write to log file
  if (kernel_write(file, line, len, &file->f_pos) < 0) {
    pr_err("%s: kernel_write failed in write_to_log\n", MODNAME);
    pr_info("%s-log: %s\n", MODNAME, line);
    goto exit;
  }

exit:
  // Freeing work structure
  if (work->program_path)
    kfree(work->program_path);
  if (work->primary_file_path)
    kfree(work->primary_file_path);
  if (work->secondary_file_path)
    kfree(work->secondary_file_path);
  if (hash)
    kfree(hash);
  if (file && !IS_ERR(file))
    filp_close(file, NULL);
  if (line)
    kfree(line);
  kfree(work);
}
