#ifndef RM_FS_H
#define RM_FS_H

#ifndef __KERNEL__
#include <fcntl.h>
#include <stdint.h>
#else
#include "../sffs.h"
#include <linux/fs.h>
#include <linux/types.h>

int fs_init(void);
void fs_kill_sb(struct super_block *);
struct dentry *fs_mount(struct file_system_type *, int, const char *, void *);
int fs_fill_sb(struct super_block *, void *, int);

// File operations
struct dentry *fs_lookup(struct inode *, struct dentry *, unsigned int);
ssize_t fs_read(struct file *, char *, size_t, loff_t *);
int fs_open(struct inode *, struct file *);
ssize_t fs_write_iter(struct kiocb *, struct iov_iter *);

// Dir operations
int fs_iterate(struct file *, struct dir_context *);
#endif

#define MAGIC 0x42424242
#define DEFAULT_BLOCK_SIZE 4096
#define SB_BLOCK_NUMBER 0
#define DEFAULT_FILE_INODE_BLOCK 1

#define FILENAME_MAXLEN 255

#define FS_ROOT_INODE_NUMBER 10
#define FS_FILE_INODE_NUMBER 1
#define FS_INODES_BLOCK_NUMBER 1

#define UNIQUE_FILE_NAME "reference_monitor.log"

// inode definition
struct fs_inode {
  mode_t mode;
  uint64_t inode_no;
  uint64_t data_block_number;

  union {
    uint64_t file_size;
    uint64_t dir_children_count;
  };
};

// Dir definition
struct fs_dir_record {
  char filename[FILENAME_MAXLEN];
  uint64_t inode_no;
};

// SuperBlock definition
struct fs_sb_info {
  uint64_t version;
  uint64_t magic;
  uint64_t block_size;
  uint64_t inodes_count;
  uint64_t free_blocks;

  char padding[(4 * 1024) - (5 * sizeof(uint64_t))];
};

#endif // !RM_FS_H
