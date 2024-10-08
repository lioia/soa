#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/slab.h>

#include "../reference_monitor.h"
#include "../utils/utils.h"
#include "tasks.h"

void write_to_log(unsigned long data) {
  struct reference_monitor_packed_work *work = NULL;
  char *hash = NULL, *line = NULL, *primary_file_path = NULL, *secondary_file_path = NULL;
  struct file *file = NULL;
  size_t len = 0, hash_len = 2 * SHA_LENGTH;

  // Get the work
  work = container_of((void *)data, struct reference_monitor_packed_work, the_work);

  primary_file_path = work->primary_file_path == NULL ? "" : work->primary_file_path;
  secondary_file_path = work->secondary_file_path == NULL ? "" : work->secondary_file_path;

  // Calculate hash of offending program contents
  hash = crypt_data(work->program_path, true);
  if (hash == NULL) {
    pr_err("%s: crypt_data failed in write_to_log\n", MODNAME);
    hash = "unavailable";
    hash_len = 10;
  }

  // Create output string

  // Calculating overfitted buffer for line
  // - 7: max length of operation (symlink)
  // - 4 * 10: max number of digits for the ids
  // - 9: commas, newline, NULL-terminator
  len =
      7 + 4 * 10 + work->primary_file_path_len + work->secondary_file_path_len + work->program_path_len + hash_len + 9;

  line = kzalloc(sizeof(*line) * len, GFP_KERNEL);
  if (line == NULL) {
    pr_err("%s: kmalloc for line failed in write_to_log\n", MODNAME);
    pr_info("%s-log: %s,%d,%d,%d,%d,%s,%s,%s,%s\n", MODNAME, work->operation, work->tgid, work->tid, work->uid,
            work->euid, primary_file_path, secondary_file_path, work->program_path, hash);
    goto exit;
  }

  // len now contains the actual length of the formatted string (line is still overfitted)
  len = scnprintf(line, len, "%s,%d,%d,%d,%d,%s,%s,%s,%s\n", work->operation, work->tgid, work->tid, work->uid,
                  work->euid, primary_file_path, secondary_file_path, work->program_path, hash);

  // Open log file
  file = filp_open(FS_PATH, O_WRONLY, 0644);
  if (IS_ERR(file)) {
    pr_err("%s: filp_open failed in write_to_log (%ld)\n", MODNAME, PTR_ERR(file));
    pr_info("%s-log: %s\n", MODNAME, line);
    goto exit;
  }

  // Write to log file len bytes from line
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
  if (hash && hash_len != 10)
    kfree(hash);
  if (file && !IS_ERR(file))
    filp_close(file, NULL);
  if (line)
    kfree(line);
  kfree(work);
}
