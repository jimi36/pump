#include <stdio.h>
#include <iostream>

#include <pump/utils/features.h>
#include <pump/time/timestamp.h>

int main(int argc, const char **argv)
{
	int c = 1;

	pump::utils::scoped_defer defer([&]() {
		printf("c=%d\n", c);
	});
	defer.clear();

	printf("c=%d\n", c);

	c = 2;

	return  0;
}