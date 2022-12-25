#include <stdio.h>

void print_string(char *s) {
  printf("%s\n", s);
}

int main(int argc, char **argv, char **envp) {
  print_string("Hello world (0)");
  print_string("Hello world (1)");
  print_string("Hello world (2)");
  return 0;
}