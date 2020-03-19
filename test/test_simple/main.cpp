#include <stdio.h>
#include <iostream>

#include <pump/time/timestamp.h>

int get_rand()
{
	return pump::time::get_clock_microsecond();
}

class MyTest
{
public:
	MyTest()
	{
		auto f = []() { return pump::time::get_clock_microsecond(); };
		func_ = function::bind(::get_rand);
		func1_ = std::bind(::get_rand);
	}

	int get_rand_by_virtaul() 
	{
		return get_rand();
	}

	int get_rand_by_func() 
	{
		return func_();
	}

	int get_rand_by_func1()
	{
		return func1_();
	}

private:
	virtual int get_rand() = 0;

private:
	function::function<int()> func_;
	std::function<int()> func1_;
};

class MySubTest: public MyTest
{
public:
	MySubTest() {}

	virtual int get_rand()
	{
		return pump::time::get_clock_microsecond();
	}
};

int main(int argc, const char **argv)
{
	int fd = 10;
	int fdd = fd; fd = -1;
	printf("fd=%d fdd=%d\n", fd, fdd);

	std::shared_ptr<MySubTest> t_spr(new MySubTest());
	//MySubTest *t = t_spr.get();

	int loop = 50000000;

	Sleep(2000);

	int n = 0;
	auto beg1 = pump::time::get_clock_milliseconds();
	for (size_t i = 0; i < loop; i++)
	{
		MySubTest *t = t_spr.get();
		if (!t) continue;
		n ^= t->get_rand_by_virtaul();
		n ^= t->get_rand_by_virtaul();
	}
	auto end1 = pump::time::get_clock_milliseconds();
	printf("ptr %d %llu\n", n, end1 - beg1);

	int nn = 0;
	auto beg2 = pump::time::get_clock_milliseconds();
	for (size_t i = 0; i < loop; i++)
	{
		if (!t_spr) continue;
		nn ^= t_spr->get_rand_by_virtaul();
		nn ^= t_spr->get_rand_by_virtaul();
	}
	auto end2 = pump::time::get_clock_milliseconds();
	printf("sptr %d %llu\n", nn, end2 - beg2);

	ssize_t i = 0;

	/*
	int n = 0;
	auto beg1 = pump::time::get_clock_milliseconds();
	for (size_t i = 0; i < loop; i++)
	{
		n ^= t->get_rand_by_virtaul();
	}
	auto end1 = pump::time::get_clock_milliseconds();
	printf("virtual %d %llu\n", n, end1 - beg1);

	int nn = 0;
	auto beg2 = pump::time::get_clock_milliseconds();
	for (size_t i = 0; i < loop; i++)
	{
		nn ^= t->get_rand_by_func();
	}
	auto end2 = pump::time::get_clock_milliseconds();
	printf("func %d %llu\n", nn, end2 - beg2);

	int nnn = 0;
	auto beg3 = pump::time::get_clock_milliseconds();
	for (size_t i = 0; i < loop; i++)
	{
		nnn ^= t->get_rand_by_func1();
	}
	auto end3 = pump::time::get_clock_milliseconds();
	printf("func1 %d %llu\n", nn, end3 - beg3);

	int nnnn = 0;
	auto beg4 = pump::time::get_clock_milliseconds();
	for (size_t i = 0; i < loop; i++)
	{
		nnnn ^= get_rand();
	}
	auto end4 = pump::time::get_clock_milliseconds();
	printf("func ptr %d %llu\n", nn, end4 - beg4);
	*/

	return  0;
}