#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include <queue>
#include <mutex>
#include <new>

#include <pump/time/timestamp.h>
#include <pump/toolkit/features.h>
#include <pump/toolkit/freelock_m2m_queue.h>
#include <pump/toolkit/freelock_o2o_queue.h>

#include "concurrentqueue.h"
#include "readerwriterqueue.h"

using namespace pump;

int test1(int loop) {
    int val;

    toolkit::freelock_o2o_queue<int, 256> sq(1024);

    std::thread t1([&]() {
        auto beg = time::get_clock_microseconds();
        for (int i = 0; i < loop;) {
            if (sq.push(i)) {
                i++;
            }
        }
        auto end = time::get_clock_microseconds();
        printf("single_freelock_list_queue push use %dus category %d\n",
               int(end - beg),
               sq.capacity());
    });

    auto beg = time::get_clock_microseconds();
    for (int i = 0; i < loop;) {
        if (sq.pop(val)) {
            if (val != i) {
                printf("single_freelock_list_queue pop %d != %d\n", val, i);
                return -1;
            }
            i++;
        }
    }
    auto end = time::get_clock_microseconds();
    printf("single_freelock_list_queue pop use %dus\n", int(end - beg));

    t1.join();

    std::mutex mx;
    std::queue<int> pq;
    // std::priority_queue<int> ppq;

    std::thread t2([&]() {
        auto beg = time::get_clock_microseconds();
        for (int i = 0; i < loop; i++) {
            mx.lock();
            pq.push(i);
            mx.unlock();
        }
        auto end = time::get_clock_microseconds();
        printf("std_queue push use %dus\n", int(end - beg));
    });

    beg = time::get_clock_microseconds();
    for (int i = 0; i < loop;) {
        mx.lock();
        if (!pq.empty()) {
            val = pq.front();
            pq.pop();

            if (val != i) {
                printf("std_queue pop %d != %d\n", val, i);
                return -1;
            }
            i++;
        }
        mx.unlock();
    }
    end = time::get_clock_microseconds();
    printf("std_queue pop use %dus\n", int(end - beg));

    t2.join();

    moodycamel::ReaderWriterQueue<int> cq;

    std::thread t4([&]() {
        auto beg = time::get_clock_microseconds();
        for (int i = 0; i < loop;) {
            if (cq.enqueue(i)) {
                i++;
            }
        }
        auto end = time::get_clock_microseconds();
        printf("moodycamel::ReaderWriterQueue push use %dus\n", int(end - beg));
    });

    beg = time::get_clock_microseconds();
    for (int i = 0; i < loop;) {
        if (cq.try_dequeue(val)) {
            if (val != i) {
                printf("ReaderWriterQueue pop %d != %d\n", val, i);
                return -1;
            }
            i++;
        }
    }
    end = time::get_clock_microseconds();
    printf("moodycamel::ReaderWriterQueue pop use %dus\n", int(end - beg));

    t4.join();

    return 0;
}

int test2(int loop) {
    int pop_thread_cnt = 5;
    int push_thread_cnt = 5;
    std::vector<std::thread *> threads;

    std::atomic_int32_t sum(0);
    int pop_loop = loop * push_thread_cnt / pop_thread_cnt;

    toolkit::freelock_m2m_queue<int> m2m_q(512);
    for (int i = 0; i < push_thread_cnt; i++) {
        std::thread *t = new std::thread([&]() {
            auto beg = time::get_clock_microseconds();
            for (int ii = 0; ii < loop;) {
                if (m2m_q.push(ii)) {
                    ii++;
                }
            }
            auto end = time::get_clock_microseconds();
            printf("freelock_m2m_queue push use %dus category %d\n",
                   int(end - beg),
                   m2m_q.capacity());
        });
        threads.push_back(t);
    }

    for (int i = 0; i < pop_thread_cnt; i++) {
        std::thread *t = new std::thread([&]() {
            int val;
            auto beg = time::get_clock_microseconds();
            for (int ii = 0; ii < pop_loop;) {
                if (m2m_q.pop(val)) {
                    sum.fetch_add(val);
                    ii++;
                }
            }
            auto end = time::get_clock_microseconds();
            printf("freelock_m2m_queue pop use %dus\n", int(end - beg));
        });
        threads.push_back(t);
    }

    for (auto b = threads.begin(); b != threads.end(); b++) {
        (*b)->join();
        delete (*b);
    }
    threads.clear();

    printf("freelock_m2m_queue sum %d %d\n", m2m_q.no_constructor, sum.load());

    moodycamel::ConcurrentQueue<int> cq;
    for (int i = 0; i < push_thread_cnt; i++) {
        std::thread *t = new std::thread([&]() {
            auto beg = time::get_clock_microseconds();
            for (int ii = 0; ii < loop;) {
                if (cq.enqueue(ii)) {
                    ii++;
                }
            }
            auto end = time::get_clock_microseconds();
            printf("moodycamel::ConcurrentQueue push use %dus\n", int(end - beg));
        });
        threads.push_back(t);
    }

    sum.store(0);
    for (int i = 0; i < pop_thread_cnt; i++) {
        std::thread *t = new std::thread([&]() {
            int val;
            auto beg = time::get_clock_microseconds();
            for (int ii = 0; ii < pop_loop;) {
                if (cq.try_dequeue(val)) {
                    sum.fetch_add(val);
                    ii++;
                }
            }
            auto end = time::get_clock_microseconds();
            printf("moodycamel::ConcurrentQueue pop use %dus\n", int(end - beg));
        });
        threads.push_back(t);
    }

    for (auto b = threads.begin(); b != threads.end(); b++) {
        (*b)->join();
        delete (*b);
    }
    threads.clear();

    printf("moodycamel::ConcurrentQueue sum %d\n", sum.load());

    std::mutex mx;
    std::queue<int> pq;
    // std::priority_queue<int> ppq;
    for (int i = 0; i < push_thread_cnt; i++) {
        std::thread *t = new std::thread([&]() {
            auto beg = time::get_clock_microseconds();
            for (int ii = 0; ii < loop; ii++) {
                mx.lock();
                pq.push(ii);
                mx.unlock();
            }
            auto end = time::get_clock_microseconds();
            printf("std_queue push use %dus\n", int(end - beg));
        });
        threads.push_back(t);
    }

    sum.store(0);
    for (int i = 0; i < pop_thread_cnt; i++) {
        std::thread *t = new std::thread([&]() {
            int val;
            auto beg = time::get_clock_microseconds();
            for (int ii = 0; ii < pop_loop;) {
                mx.lock();
                if (!pq.empty()) {
                    val = pq.front();
                    pq.pop();

                    sum.fetch_add(val);

                    ii++;
                }
                mx.unlock();
            }
            auto end = time::get_clock_microseconds();
            printf("std_queue pop use %dus\n", int(end - beg));
        });
        threads.push_back(t);
    }

    for (auto b = threads.begin(); b != threads.end(); b++) {
        (*b)->join();
        delete (*b);
    }
    threads.clear();

    printf("std_queue sum %d\n", sum.load());

    return 0;
}

int main(int argc, const char **argv) {
    int i = 0;
    defer_call_begin
        printf("%d\n", ++i);
    defer_call_end
    defer_call_begin
        printf("%d\n", ++i);
    defer_call_end
    if (argc < 2) {
        return -1;
    }

    std::string test_case = argv[1];
    int loop = atoi(argv[2]);

    if (test_case == "test1") {
        test1(loop);
    }
    if (test_case == "test2") {
        test2(loop);
    }

    return 0;
}
