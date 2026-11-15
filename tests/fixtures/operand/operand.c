// Operand-only change fixture (from the wt-678 blind-spot harness). One function, four variants,
// all the same size except `struct`:
//   same    no change                               control: must report nothing
//   const   a bounds constant   (n > 64 -> n > 32)  cmp #0x40 -> cmp #0x20
//   stack   a buffer size       (256 -> 128)        sub sp,#0x140 -> sub sp,#0xc0 (the MS03-026 shape)
//   struct  an added statement  (extra if)          size changes
// check() is also inlined into main(), so each change appears in two functions.
#include <string.h>

#ifndef BOUND
#define BOUND 64
#endif
#ifndef STACKSIZE
#define STACKSIZE 256
#endif

int check(const char *in, char *out) {
    char scratch[STACKSIZE];
    size_t n = strlen(in);
    if (n > BOUND) return -1;
#ifdef EXTRA_CHECK
    if (!out) return -2;
#endif
    memcpy(scratch, in, n);
    memcpy(out, scratch, n);
    return (int)n;
}

int main(int c, char **v) { char b[512]; return check(v[0], b); }
