#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

int get_integer(char *prompt) {
  while (1) {
    printf("%s", prompt);
    int extra = 0;
    int command = getchar();
    if (command == '\n')
      continue;
    char ch;
    while (((ch = (char)getchar()) != EOF) && (ch != '\n'))
      extra++;
    if (command == EOF || ch == EOF) {
      printf("EOF received, leaving...\n");
      return -1;
    }

    if (extra > 1)
      continue;
    return command - '0';
  }
}

char *get_string(int hide) {
  struct termios term, oterm;
  char c;
  int i = 0;
  char *buffer = malloc(sizeof(*buffer) * 1024);
  if (buffer == NULL) {
    perror("malloc for buffer failed in get_string\n");
    return NULL;
  }
  if (hide) {
    if (tcgetattr(fileno(stdin), &oterm) == 0) {
      memcpy(&term, &oterm, sizeof(struct termios));
      /*term.c_lflag &= ~(ECHO | ECHONL);*/
      term.c_lflag &= ~(ECHO | ECHONL | ICANON);
      tcsetattr(fileno(stdin), TCSAFLUSH, &term);
    } else {
      memset(&term, 0, sizeof(struct termios));
      memset(&oterm, 0, sizeof(struct termios));
    }
    while ((c = getchar()) != '\n' && c != EOF && i < 1024 - 1) {
      if (c == 127) { // BACKSPACE
        if (i > 0) {
          i--;
          printf("\b \b"); // Move cursor back, print space, move cursor back again
        }
      } else {
        buffer[i++] = c;
        printf("*");
        fflush(stdout);
      }
    }
    buffer[i] = '\0'; // Null-terminate the password string

    // Return to original state
    puts("");
    tcsetattr(fileno(stdin), TCSAFLUSH, &oterm);
  } else {
    if (fgets(buffer, 1024, stdin) == NULL) {
      perror("fgets failed in get_string\n");
      free(buffer);
      return NULL;
    }
    int len = strlen(buffer);
    if (len < 0 || buffer[len - 1] != '\n') {
      fprintf(stderr, "input too big");
      free(buffer);
      return NULL;
    }

    buffer[len - 1] = '\0';
    buffer = realloc(buffer, sizeof(*buffer) * len);
  }

  return buffer;
}
