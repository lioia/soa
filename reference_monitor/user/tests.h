#ifndef TESTS
#define TESTS

// Tests
int run_test(int (*func)(void), char *password);
int create_test(void);
int open_test(void);
int unlink_test(void);
int link_test(void);
int mkdir_test(void);
int rmdir_test(void);
int rename_test(void);
int symlink_test(void);

int setup(void);
int cleanup(char *path);

#endif // !TESTS
