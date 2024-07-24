#ifndef IO_H

#define flush(stdin)                                                                                                   \
  do {                                                                                                                 \
    int c;                                                                                                             \
    while ((c = getchar()) != '\n' && c != EOF)                                                                        \
      ;                                                                                                                \
  } while (0)

#define clear() printf("\033[2J\033[H")

int get_integer(char *prompt);
char *get_string(int hide);

#endif // !IO_H
