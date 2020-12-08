#include <stdlib.h>
#include <stdio.h>
#include <thread>

#include <pump/time/timestamp.h>
#include <pump/toolkit/mutil_freelock_queue.h>
#include <pump/toolkit/single_freelock_queue.h>

#include "concurrentqueue.h"
#include "readerwriterqueue.h"

using namespace pump;

static int32_t ceilToPow2(int32_t x) {
	// From http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
	--x;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	for (int32_t i = 1; i < sizeof(int32_t); i <<= 1) {
		x |= x >> (i << 3);
	}
	++x;
	return x;
}

int main(int argc, const char **argv) {
    if (argc < 2) {
        return -1;
    }

    int val;
    int loop = atoi(argv[1]);

    auto x = ceilToPow2(loop);
    printf("x=%u\n", x);

    toolkit::single_freelock_queue<int, 256> sq(1024);

    std::thread t1([&](){
        {
        auto beg = time::get_clock_milliseconds();
        for (int i = 0; i < loop;) {
            if (sq.push(i)) {
                i++;
            }
        }
        auto end = time::get_clock_milliseconds();
        printf("single_freelock_list_queue push use %dms category %d\n", int(end-beg), sq.capacity());
        }
    });

    auto beg = time::get_clock_milliseconds();
    for (int i = 0; i < loop;) {
        if (sq.pop(val)) {
            if (val != i) {
                printf("pop %d != %d\n", val, i);
                return -1;
            }
            i++;
        }
    }
    auto end = time::get_clock_milliseconds();
    printf("single_freelock_list_queue pop use %dms\n", int(end-beg));

    t1.join();
    
    toolkit::mutil_freelock_queue<int> q(1024);

    std::thread t2([&](){
        auto beg = time::get_clock_milliseconds();
        for (int i = 0; i < loop;) {
            if (q.push(i)) {
                i++;
            }
        }
        auto end = time::get_clock_milliseconds();
        printf("freelock_list_queue push use %dms category %d\n", int(end-beg), q.capacity());
    });

    beg = time::get_clock_milliseconds();
    for (int i = 0; i < loop;) {
        if (q.pop(val)) {
            if (val != i) {
                printf("pop %d != %d\n", val, i);
                return -1;
            }
            i++;
        }
    }
    end = time::get_clock_milliseconds();
    printf("freelock_list_queue pop use %dms\n", int(end-beg));

    t2.join();
    
    moodycamel::ReaderWriterQueue<int> cq;

    std::thread t3([&](){
        auto beg = time::get_clock_milliseconds();
        for (int i = 0; i < loop;) {
            if (cq.enqueue(i)) {
                i++;
            }
        }
        auto end = time::get_clock_milliseconds();
        printf("moodycamel::ReaderWriterQueue push use %dms\n", int(end-beg));
    });

    beg = time::get_clock_milliseconds();
    for (int i = 0; i < loop;) {
        if (cq.try_dequeue(val)) {
            if (val != i) {
                printf("pop %d != %d\n", val, i);
                return -1;
            }
            i++;
        }
    }
    end = time::get_clock_milliseconds();
    printf("moodycamel::ReaderWriterQueue pop use %dms\n", int(end-beg));

    t3.join();


    return 0;
}