#include <stdio.h>

int add (int a, int b, int c) {
    return a + b + c;
}

int main(int argc, char **argv, char **envp) {
    int a, b, c;
    a = 1;
    b = 2;
    c = 9;
    printf("a = %d, b = %d, c = %d\n", a, b, c);

    int d = add(a, b, 23); // 1(1) + 2(2) + 23(17) = 26(1a)
    printf("%d + %d + %d = %d\n", a, b, 23, d);
    int e = add(d, c, 54); // 26(1a) + 9(9) + 54(36) = 89(59)
    printf("%d + %d + %d = %d\n", d, c, 54, e);
    int f = add(e, 1, 7);  // 89(59) + 1(1) + 7(7) = 97(61)
    printf("%d + %d + %d = %d\n", e, 1, 7, f);
    return 0;
}