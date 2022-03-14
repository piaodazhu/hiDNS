#include "security.h"
int checksignature()
{
	// haven't implemented
	return 0;
}

void onewayhash128(char *x)
{
	// haven't implemented
	x[15] += 1;
	return;
}

int checktoken_hash128(char *start, char *end, int k)
{
	return 1;
	// int i;
	// char x[16];
	// memcpy(x, start, 16);
	// // at least once
	// onewayhash128(x);
	// for (i = 0; i < k - 1; i++) {
	// 	if (!memcmp(x, end, 16))
	// 		return 1;
	// 	onewayhash128(x);
	// }
	// return 0;
}

