#include <stdio.h>
__thread int t = 3; int g = 42; const char *m = "hi";
int f(int n){ return n < 2 ? n : f(n-1) + f(n-2); }
int main(int c, char **v){ switch (c % 3) { case 0: puts("a"); break; case 1: puts("b"); break; default: puts("c"); }
  printf("%d %d %s\n", f(10), g + t, m); return c % 2; }
