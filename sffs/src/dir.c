#include "fs.h"

#include <linux/fs.h>

// This returns 3 entries: ., .. and unique file name
int fs_iterate(struct file *file, struct dir_context *ctx) {
  // There is only the ., .. and the unique file name
  if (ctx->pos >= (2 + 1))
    return 0;

  if (ctx->pos == 0) {
    if (!dir_emit(ctx, ".", FILENAME_MAXLEN, FS_ROOT_INODE_NUMBER, DT_UNKNOWN))
      return 0;

    ctx->pos++;
  }

  if (ctx->pos == 1) {
    // Inode number is not important
    if (!dir_emit(ctx, ".", FILENAME_MAXLEN, 1, DT_UNKNOWN))
      return 0;

    ctx->pos++;
  }

  if (ctx->pos == 2) {
    if (!dir_emit(ctx, UNIQUE_FILE_NAME, FILENAME_MAXLEN, FS_FILE_INODE_NUMBER, DT_UNKNOWN))
      return 0;

    ctx->pos++;
  }

  return 0;
}
