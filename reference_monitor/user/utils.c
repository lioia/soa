#include "utils.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int check_if_module_is_inserted() {
  FILE *fp;
  char live[4];
  char *path = "/sys/module/the_reference_monitor/initstate";
  if (access(path, R_OK) != 0) {
    fprintf(stderr, "Module is not loaded\n");
    return -1;
  }
  fp = fopen(path, "r");
  if (fp == NULL) {
    fprintf(stderr, "Failed to read module initstate");
    return -1;
  }
  fread(live, sizeof(*live), 4, fp);
  return strncmp(live, "live", 4);
}

char *resolve_path(char *path) {
  if (path[0] == '~') {
    fprintf(stderr, "Cannot resolve '~'\n");
    return NULL;
  }

  char *resolved_path = realpath(path, NULL);
  if (resolved_path == NULL) {
    perror("realpath failed in resolve_path");
    return NULL;
  }

  return resolved_path;
}
