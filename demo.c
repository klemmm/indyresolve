#include <stdio.h>

typedef int (func_t)(void);

int foo(void) {
	return 1;
}

int bar(void) {
	return 2;
}

func_t *getf(int x) {
	func_t *f;
	if (x > 1) {
		f = bar;
	} else {
		f = foo;
	}
}

int main(int argc, char **argv) {
	func_t *f;

	f = getf(argc);

	printf("Calling f()\n");
	return f();
}

