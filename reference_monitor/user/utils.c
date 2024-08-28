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
  int len = PATH_MAX;
  char *resolved_path = malloc(sizeof(*resolved_path) * len);
  if (resolved_path == NULL) {
    perror("malloc failed in resolve_path");
    return NULL;
  }

  if (path[0] == '~') {
    char *home_dir = getenv("HOME");
    if (home_dir == NULL) {
      perror("getenv for HOME failed in resolve_path");
      return NULL;
    }

    len = snprintf(resolved_path, len, "%s%s", home_dir, path + 1);
    resolved_path = realloc(resolved_path, sizeof(*resolved_path) * len);
    if (resolved_path == NULL) {
      perror("realloc failed in resolve_path");
      return NULL;
    }
  } else {
    strncpy(resolved_path, path, len);
  }

  if (realpath(resolved_path, resolved_path) == NULL) {
    perror("realpath failed in resolve_path");
    return NULL;
  }

  return resolved_path;
}
