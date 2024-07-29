#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "fs.h"

int main(int argc, char *argv[]) {
  int fd, nbytes;
  int ret;
  struct fs_sb_info sb;
  struct fs_inode file_inode;
  char *block_padding;

  if (argc != 2) {
    printf("Usages: %s <device>\n", argv[0]);
    return EXIT_FAILURE;
  }

  fd = open(argv[1], O_RDWR);
  if (fd < 0) {
    perror("Error opening the device");
    return EXIT_FAILURE;
  }

  // SuperBlock information
  sb.version = 1;
  sb.magic = MAGIC;
  sb.block_size = DEFAULT_BLOCK_SIZE;

  ret = write(fd, (char *)&sb, sizeof(sb));
  if (ret != DEFAULT_BLOCK_SIZE) {
    fprintf(stderr, "SuperBlock was not written properly; written %d bytes, expected %d\n", ret, DEFAULT_BLOCK_SIZE);
    goto exit;
  }

  puts("SuperBlock written successfully");

  // File inode
  file_inode.mode = S_IFREG;
  file_inode.inode_no = FS_FILE_INODE_NUMBER;
  file_inode.file_size = 0;

  ret = write(fd, (char *)&file_inode, sizeof(file_inode));
  if (ret != sizeof(file_inode)) {
    fprintf(stderr, "File inode was not written properly; written %d bytes, expected %d\n", ret,
            (int)sizeof(file_inode));
    goto exit;
  }
  puts("SuperBlock written successfully");

  // Padding for block 1
  nbytes = DEFAULT_BLOCK_SIZE - sizeof(file_inode);
  block_padding = malloc(nbytes);
  if (block_padding == NULL) {
    perror("Failed to allocate block_padding");
    ret = EXIT_FAILURE;
    goto exit;
  }

  ret = write(fd, block_padding, nbytes);
  if (ret != nbytes) {
    fprintf(stderr, "Padding was not written properly; written %d bytes, expected %d\n", ret, nbytes);
    goto exit;
  }
  // No error
  ret = 0;

exit:
  close(fd);
  return ret;
}
