#include <pump/service.h>
#include <pump/times.h>
#include <pump/utils/freelock.h>

int main(int argc, const char **argv)
{
	pump::utils::freelock_list<int> flist(100);
	std::list<int> slist;

	auto b = pump::get_clock_milliseconds();
	for (int i = 0; i < 10000; i++)
	{
		flist.push(i);
	}
	auto e = pump::get_clock_milliseconds();
	printf("lock free list push used %llu\n", e - b);
	
	b = pump::get_clock_milliseconds();
	for (int i = 0; i < 10000; i++)
	{
		slist.push_back(i);
	}
	e = pump::get_clock_milliseconds();
	printf("std list push used %llu\n", e - b);

	int data;
	b = pump::get_clock_milliseconds();
	for (int i = 0; i < 10001; i++)
	{
		assert(flist.pop(data));
	}
	e = pump::get_clock_milliseconds();
	printf("free lock list pop used %llu\n", e - b);

	b = pump::get_clock_milliseconds();
	for (int i = 0; i < 1000; i++)
	{
		slist.pop_front();
	}
	e = pump::get_clock_milliseconds();
	printf("std list pop used %llu\n", e - b);

	return  0;
}