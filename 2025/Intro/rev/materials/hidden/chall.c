#include <stdio.h>
#include <string.h>
#include <stdbool.h>

const char target[] = "<><<<>>=<>>=<>>><<>=<>>><><=<><<><=<><<<><=<>>>>=<<>><=<>><<<=<<>>=<>=<><>><=<<>><<<=<>>><>=<>>><<>=<>=<><><>>=<<>><=<>><=<>><=<<>><<=<>><<>=<<>><>=<>=<<>><><=<>><>>>=<>><<><=<>=<><<>><=<<>><=<>>><<>=<>><>>>=<>=<><>><=<<>><<<=<>>><>=<>>><<>=<>=<><<<>>=<>>><>=<>><>>>=<>><<><=<<>><><=<>><>>=<<>><=<>><>>>=<<>>=<<>><><=<<>><<=<>=<><><=<<>><=<>><<<=<>>><<>=<>><<=<>><><<=<>=<><<<<=<>><>><=<>><=<<>><<<=<>>><<>=<<>><<=<<>>=<>><><<=<>><>>=<<>><>=<>>>>>=";

int main(void) {
  char s[70], enc[512];
  printf("Enter flag: ");
  scanf("%s", s);

  if (strlen(s) > 70) {
    printf("Nope\n");
    return 0;
  }

  int j = 0;
  for (int i = 0; i < strlen(s); ++i) {
    int lo = 0, hi = 255;
    while (true) {
      int mid = (lo + hi) / 2;
      if (mid == s[i]) {
        enc[j++] = '=';
        break;
      }
      if (mid < s[i]) {
        enc[j++] = '>';
        lo = mid + 1;
      } else {
        enc[j++] = '<';
        hi = mid - 1;
      }
    }
  }

  if (j != strlen(target)) {
    printf("Nope\n");
    return 0;
  }

  for (int i = 0; i < strlen(target); ++i) {
    if (enc[i] != target[i]) {
      printf("Nope\n");
      return 0;
    }
  }

  printf("Correct!\n");
  return 0;
}
