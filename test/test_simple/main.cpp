#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include <queue>
#include <mutex>

#include <pump/time/timestamp.h>
#include <pump/toolkit/freelock_multi_queue.h>
#include <pump/toolkit/freelock_single_queue.h>

#include "concurrentqueue.h"
#include "readerwriterqueue.h"

using namespace pump;

int test1(int loop) {

    int val;

    toolkit::freelock_single_queue<int, 256> sq(1024);

    std::thread t1([&]() {
        {
            auto beg = time::get_clock_milliseconds();
            for (int i = 0; i < loop;) {
                if (sq.push(i)) {
                    i++;
                }
            }
            auto end = time::get_clock_milliseconds();
            printf("single_freelock_list_queue push use %dms category %d\n", int(end - beg), sq.capacity());
        }
        });

    auto beg = time::get_clock_milliseconds();
    for (int i = 0; i < loop;) {
        if (sq.pop(val)) {
            //if (val != i) {
            //    printf("single_freelock_list_queue pop %d != %d\n", val, i);
            //    return -1;
            //}
            i++;
        }
    }
    auto end = time::get_clock_milliseconds();
    printf("single_freelock_list_queue pop use %dms\n", int(end - beg));

    t1.join();

    toolkit::freelock_multi_queue<int> q(1024);

    std::thread t2([&]() {
        int loop2 = loop / 2;
        auto beg = time::get_clock_milliseconds();
        for (int i = 0; i < loop2;) {
            if (q.push(i)) {
                i++;
            }
        }
        auto end = time::get_clock_milliseconds();
        printf("freelock_list_queue push use %dms category %d\n", int(end - beg), q.capacity());
    });

    std::thread t3([&]() {
        auto beg = time::get_clock_milliseconds();
        for (int i = loop /2; i < loop;) {
            if (q.push(i)) {
                i++;
            }
        }
        auto end = time::get_clock_milliseconds();
        printf("freelock_list_queue push use %dms category %d\n", int(end - beg), q.capacity());
        });

    beg = time::get_clock_milliseconds();
    for (int i = 0; i < loop;) {
        if (q.pop(val)) {
            //if (val != i) {
            //    printf("multi_freelock_queue pop %d != %d\n", val, i);
            //    return -1;
            //}
            i++;
        }
    }
    end = time::get_clock_milliseconds();
    printf("freelock_list_queue pop use %dms\n", int(end - beg));

    t2.join();
    t3.join();

    moodycamel::ReaderWriterQueue<int> cq;

    std::thread t4([&]() {
        auto beg = time::get_clock_milliseconds();
        for (int i = 0; i < loop;) {
            if (cq.enqueue(i)) {
                i++;
            }
        }
        auto end = time::get_clock_milliseconds();
        printf("moodycamel::ReaderWriterQueue push use %dms\n", int(end - beg));
        });

    beg = time::get_clock_milliseconds();
    for (int i = 0; i < loop;) {
        if (cq.try_dequeue(val)) {
            //if (val != i) {
            //    printf("ReaderWriterQueue pop %d != %d\n", val, i);
            //    return -1;
            //}
            i++;
        }
    }
    end = time::get_clock_milliseconds();
    printf("moodycamel::ReaderWriterQueue pop use %dms\n", int(end - beg));

    t4.join();

    return 0;
}

int test2(int loop) {

    int val;

    toolkit::freelock_multi_queue<int> q(1024);

    std::thread t1([&]() {
        int loop2 = loop / 2;
        auto beg = time::get_clock_milliseconds();
        for (int i = 0; i < loop2;) {
            if (q.push(i)) {
                i++;
            }
        }
        auto end = time::get_clock_milliseconds();
        printf("multi_freelock_queue push use %dms category %d\n", int(end - beg), q.capacity());
        });

    std::thread t2([&]() {
        auto beg = time::get_clock_milliseconds();
        for (int i = loop / 2; i < loop;) {
            if (q.push(i)) {
                i++;
            }
        }
        auto end = time::get_clock_milliseconds();
        printf("multi_freelock_queue push use %dms category %d\n", int(end - beg), q.capacity());
    });

    auto beg = time::get_clock_milliseconds();
    for (int i = 0; i < loop;) {
        if (q.pop(val)) {
            //if (val != i) {
            //    printf("multi_freelock_queue pop %d != %d\n", val, i);
            //    return -1;
            //}
            i++;
        }
    }
    auto end = time::get_clock_milliseconds();
    printf("multi_freelock_queue pop use %dms\n", int(end - beg));

    t1.join();
    t2.join();

    moodycamel::ConcurrentQueue<int> cq;

    std::thread t3([&]() {
        int loop2 = loop / 2;
        auto beg = time::get_clock_milliseconds();
        for (int i = 0; i < loop2;) {
            if (cq.enqueue(i)) {
                i++;
            }
        }
        auto end = time::get_clock_milliseconds();
        printf("moodycamel::ConcurrentQueue push use %dms\n", int(end - beg));
    });

    std::thread t4([&]() {
        auto beg = time::get_clock_milliseconds();
        for (int i = loop / 2; i < loop;) {
            if (cq.enqueue(i)) {
                i++;
            }
        }
        auto end = time::get_clock_milliseconds();
        printf("moodycamel::ConcurrentQueue push use %dms\n", int(end - beg));
    });

    beg = time::get_clock_milliseconds();
    for (int i = 0; i < loop;) {
        if (cq.try_dequeue(val)) {
            //if (val != i) {
            //    printf("ReaderWriterQueue pop %d != %d\n", val, i);
            //    return -1;
            //}
            i++;
        }
    }
    end = time::get_clock_milliseconds();
    printf("moodycamel::ConcurrentQueue pop use %dms\n", int(end - beg));

    t3.join();
    t4.join();


    std::mutex mx;
    std::queue<int> pq;

    std::thread t5([&]() {
        int loop2 = loop / 2;
        auto beg = time::get_clock_milliseconds();
        for (int i = 0; i < loop2;i++) {
            mx.lock();
            pq.push(i);
            mx.unlock();
        }
        auto end = time::get_clock_milliseconds();
        printf("std_queue push use %dms\n", int(end - beg));
        });

    std::thread t6([&]() {
        auto beg = time::get_clock_milliseconds();
        for (int i = loop / 2; i < loop;i++) {
            mx.lock();
            pq.push(i);
            mx.unlock();
        }
        auto end = time::get_clock_milliseconds();
        printf("std_queue push use %dms\n", int(end - beg));
        });

    beg = time::get_clock_milliseconds();
    for (int i = 0; i < loop;) {
        mx.lock();
        if (!pq.empty()) {
            
            val = pq.front();
            pq.pop();
            
            i++;
        }
        mx.unlock();
    }
    end = time::get_clock_milliseconds();
    printf("std_queue pop use %dms\n", int(end - beg));

    t5.join();
    t6.join();

    return 0;
}

int main(int argc, const char **argv) {
    if (argc < 2) {
        return -1;
    }

    int loop = atoi(argv[1]);

    test2(loop);

    return 0;
}