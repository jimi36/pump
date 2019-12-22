#include <stdio.h>
#include <iostream>

#include <librabbit/utils/features.h>
#include <librabbit/time/timestamp.h>

int main(int argc, const char **argv)
{
	int c = 1;

	librabbit::utils::scoped_defer defer([&]() {
		printf("c=%d\n", c);
	});
	defer.clear();

	printf("c=%d\n", c);

	c = 2;

	return  0;
}