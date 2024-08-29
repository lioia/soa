#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "tests.h"
#include "user.h"
#include "utils.h"

#define TEST_ROOT "/tmp/reference-monitor-tests"
#define TEST_DIRECTORY "/tmp/reference-monitor-tests/directory"
#define TEST_DIRECTORY_FILE "/tmp/reference-monitor-tests/directory/file.txt"
#define TEST_FILE "/tmp/reference-monitor-tests/file.txt"

#define RUN_TEST(test_name, password)                                                                                  \
  do {                                                                                                                 \
    int ret = 0;                                                                                                       \
    if (setup() != 0)                                                                                                  \
      return EXIT_FAILURE;                                                                                             \
    if (syscall(SET_STATE, password, 3) != 0) {                                                                        \
      perror("Failed to set state to REC-ON");                                                                         \
      return EXIT_FAILURE;                                                                                             \
    }                                                                                                                  \
    if (syscall(ADD_PATH, password, TEST_DIRECTORY) != 0) {                                                            \
      perror("Failed to add directory to protected path");                                                             \
      return EXIT_FAILURE;                                                                                             \
    }                                                                                                                  \
    if (syscall(ADD_PATH, password, TEST_FILE) != 0) {                                                                 \
      perror("Failed to add file.txt to protected path");                                                              \
      return EXIT_FAILURE;                                                                                             \
    }                                                                                                                  \
    if ((ret = test_name##_test()) != 0)                                                                               \
      fprintf(stderr, "%s test failed\n", #test_name);                                                                 \
    if (syscall(SET_STATE, password, 0) != 0) {                                                                        \
      perror("Failed to set state to OFF");                                                                            \
      return EXIT_FAILURE;                                                                                             \
    }                                                                                                                  \
    if (cleanup(TEST_ROOT) != 0)                                                                                       \
      return EXIT_FAILURE;                                                                                             \
    if (ret != 0)                                                                                                      \
      return EXIT_FAILURE;                                                                                             \
    else                                                                                                               \
      printf("%s test was successful\n", #test_name);                                                                  \
  } while (0)

int main(void) {
  // Check if module is loaded
  if (check_if_module_is_inserted() != 0)
    exit(EXIT_FAILURE);

  printf("Enter password: ");
  char *password = get_string(false);
  if (password == NULL) {
    fprintf(stderr, "Failed to get password\n");
    return EXIT_FAILURE;
  }

  RUN_TEST(create, password);
  RUN_TEST(open, password);
  RUN_TEST(unlink, password);
  RUN_TEST(link, password);
  RUN_TEST(mkdir, password);
  RUN_TEST(rmdir, password);
  RUN_TEST(rename, password);
  RUN_TEST(symlink, password);

  puts("Tests were successful");
  return EXIT_SUCCESS;
}

// Attempts to create file or directory in protected directory
int create_test(void) {
  // Create file in protected directory
  if (open("/tmp/reference-monitor-tests/directory/new.txt", O_CREAT | O_WRONLY, 0644) != -1) {
    fprintf(stderr, "open was successful in create_test\n");
    return -1;
  }

  // Create new directory in protected directory
  if (mkdir("/tmp/reference-monitor-tests/directory/new", 0755) == 0) {
    fprintf(stderr, "mkdir was successful in create_test\n");
    return -1;
  }

  // Successful test
  return 0;
}

// Attemps to write a file in protected directory (should fail when trying to open it in write mode)
int open_test(void) {
  int fd = 0;
  char *text = "open_test";

  // Open protected file
  if ((fd = open(TEST_FILE, O_WRONLY, 0644)) == 1) {
    fprintf(stderr, "open for file in root failed in open_test\n");
    return -1;
  }
  if (write(fd, text, strlen(text)) != -1) {
    fprintf(stderr, "write for file in root was successful in open_test\n");
    return -1;
  }

  // Open file in protected directory
  if ((fd = open(TEST_DIRECTORY_FILE, O_WRONLY, 0644)) == 1) {
    fprintf(stderr, "open for file in directory failed in open_test\n");
    return -1;
  }
  if (write(fd, text, strlen(text)) != -1) {
    fprintf(stderr, "write for file in directory was successful in open_test\n");
    return -1;
  }
  return 0;
}

// Attempts to remove a protected file or file in a directory
int unlink_test(void) {
  if (unlink(TEST_FILE) == 0) {
    fprintf(stderr, "unlink for file.txt in root was successful in unlink_test\n");
    return -1;
  }

  if (unlink(TEST_DIRECTORY_FILE) == 0) {
    fprintf(stderr, "unlink for file.txt in directory was sucessful in unlink_test\n");
    return -1;
  }

  return 0;
}

// Attempts to create a hard link for a protected file or a file in a protected directory
int link_test(void) {
  if (link(TEST_FILE, "/tmp/reference-monitor-tests/new.txt") == 0) {
    fprintf(stderr, "link for file in root was successful\n");
    return -1;
  }

  if (link(TEST_DIRECTORY_FILE, "/tmp/reference-monitor-tests/new.txt") == 0) {
    fprintf(stderr, "link for file in directory was successful (outside)\n");
    return -1;
  }

  if (link(TEST_DIRECTORY_FILE, "/tmp/reference-monitor-tests/directory/new.txt") == 0) {
    fprintf(stderr, "link for file in directory was successful (inside)\n");
    return -1;
  }
  return 0;
}

// Attempts to create a directory in a protected directory
int mkdir_test(void) {
  if (mkdir("/tmp/reference-monitor-tests/directory/new", 0664) == 0) {
    fprintf(stderr, "mkdir was successful in mkdir_test\n");
    return -1;
  }
  return 0;
}

// Attempts to remove a protected directory
int rmdir_test(void) {
  if (rmdir(TEST_DIRECTORY) == 0) {
    fprintf(stderr, "rmdir was successful in rmdir_test\n");
    return -1;
  }
  return 0;
}

// Attempts to rename a protected file, a file in a protected directory or a protected directory
int rename_test(void) {
  if (rename(TEST_FILE, "/tmp/reference-monitor-tests/new.txt") == 0) {
    fprintf(stderr, "rename for file in root was successful\n");
    return -1;
  }

  if (rename(TEST_DIRECTORY_FILE, "/tmp/reference-monitor-tests/new.txt") == 0) {
    fprintf(stderr, "rename for file in directory was successful (outside)\n");
    return -1;
  }

  if (rename(TEST_DIRECTORY_FILE, "/tmp/reference-monitor-tests/directory/new.txt") == 0) {
    fprintf(stderr, "rename for file in directory was successful (inside/rename)\n");
    return -1;
  }

  if (rename(TEST_DIRECTORY, "/tmp/reference-monitor-tests/new") == 0) {
    fprintf(stderr, "rename for directory was successful\n");
    return -1;
  }

  return 0;
}

// Attempts to create a symbolic link for a protected file, protected directory or file in a protected directory
int symlink_test(void) {
  if (symlink(TEST_FILE, "/tmp/reference-monitor-tests/new.txt") == 0) {
    fprintf(stderr, "symlink for file in root was successful\n");
    return -1;
  }

  if (symlink(TEST_DIRECTORY_FILE, "/tmp/reference-monitor-tests/new.txt") == 0) {
    fprintf(stderr, "symlink for file in directory was successful (outside)\n");
    return -1;
  }

  if (symlink(TEST_DIRECTORY_FILE, "/tmp/reference-monitor-tests/directory/new.txt") == 0) {
    fprintf(stderr, "symlink for file in directory was successful (inside)\n");
    return -1;
  }

  if (symlink(TEST_DIRECTORY, "/tmp/reference-monitor-tests/new") == 0) {
    fprintf(stderr, "symlink for directory was successful\n");
    return -1;
  }

  return 0;
}

int setup(void) {
  // Create root test directory
  if (mkdir(TEST_ROOT, 0755) != 0) {
    perror("Failed to setup test environment (mkdir root)");
    return EXIT_FAILURE;
  }

  // Create protected directory
  if (mkdir(TEST_DIRECTORY, 0755) != 0) {
    puts("Failed to setup test environment (mkdir test directory)");
    return EXIT_FAILURE;
  }

  // Create not protected file in protected directory
  if (open(TEST_DIRECTORY_FILE, O_CREAT | O_WRONLY, 0644) == -1) {
    puts("Failed to setup test environment (open file in directory)");
    return EXIT_FAILURE;
  }

  // Create protected file in root
  if (open(TEST_FILE, O_CREAT | O_WRONLY, 0644) == -1) {
    puts("Failed to setup test environment (open file)");
    return EXIT_FAILURE;
  }

  return 0;
}

int cleanup(char *path) {
  DIR *dir;
  struct dirent *entry;
  struct stat statstruct;
  char fullpath[PATH_MAX];

  // Try to open path as directory
  if ((dir = opendir(path)) == NULL) {
    // Not a directory, remove the file
    return unlink(path);
  }

  // Loop through files in directory
  while ((entry = readdir(dir)) != NULL) {
    // Skip . and ..
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    // Create full path
    snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);

    // Check stats of path
    if (stat(fullpath, &statstruct) == 0) {
      if (S_ISDIR(statstruct.st_mode))
        cleanup(fullpath); // Cleanup directory recursively
      else
        unlink(fullpath); // Remove file
    }
  }

  closedir(dir); // Close directory

  return rmdir(path); // Cleanup directory
}
