#include <stdio.h>

int main() {
	volatile int flag = 0;
	if (flag == 0)
		printf("NO BEER\n");
	else
		printf("FREE BEER\n");
	return 0;
}
