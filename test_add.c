#include <stdio.h>

void add(int *num, int val) {
  *num += val;
}

int main(int argc, char **argv, char **envp) {
  int num = 0;
  int tmp = 12;
  printf("num = %d\n", num);
  add(&num, 1);
  printf("num = %d\n", num);
  add(&num, 2);
  printf("num = %d\n", num);
  add(&num, 3);
  printf("num = %d\n", num);
  return 0;
}