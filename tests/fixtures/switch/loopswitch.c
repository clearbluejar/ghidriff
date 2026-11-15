// arm64e jump-table hardening ("cmp x16, #N; csel x16, x16, xzr, ls") on a switch whose index
// comes from a loop: Ghidra's decompiler fails with "Could not execute MULTIEQUAL" and
// "Treating indirect jump as call", so all case bodies fall outside the function.
// Shape follows a metadata block parser: for each block, read an id and dispatch on 1..11.
#include <stddef.h>
#include <stdint.h>

struct reader { const uint8_t *p, *end; };

__attribute__((noinline)) static unsigned get(struct reader *r, int bits) {
	unsigned v = 0;
	for (int i = 0; i < bits / 8 && r->p < r->end; i++)
		v = (v << 8) | *r->p++;
	return v;
}

int parse_blocks(struct reader *r, int *out, int n) {
	int acc = 0;
	for (int i = 0; i < n; i++) {
		unsigned len = get(r, 16);
		unsigned id = get(r, 8);
		switch (id) {
			case 1: acc += get(r, 12); break;
			case 2: acc ^= get(r, 16) * 3; break;
			case 3: out[0] = get(r, 8); break;
			case 4: out[1] = get(r, 16) + len; break;
			case 5: acc -= get(r, 24); break;
			case 6: out[2] = (int)get(r, 8) << 2; break;
			case 7: acc |= get(r, 32); break;
			case 8: out[3] = get(r, 16) - 7; break;
			case 9: acc &= get(r, 8) | 0x100; break;
			case 10: out[4] = get(r, 24) >> 1; break;
			case 11: acc += (int)len * 5; break;
			default: return -1;
		}
	}
	return acc;
}
