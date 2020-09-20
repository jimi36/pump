#include <concurrentqueue/concurrentqueue.h>
#include <pump/codec/base64.h>
#include <pump/service.h>
#include "freelock.h"

int main(int argc, const char **argv) {
    int cnt = 10000;

    uint64_t b, e;

    moodycamel::ConcurrentQueue<int> q;

    freelock_list<int> qa(10);

    std::thread thread1([&]() {
        for (int i = 0; i < cnt / 2; i++) {
            q.enqueue(i);
        }
    });

    std::thread thread11([&]() {
        for (int i = 0; i < cnt / 2; i++) {
            q.enqueue(i);
        }
    });

    int i = 0;

    b = pump::time::get_clock_milliseconds();
    while (i < cnt) {
        int val;
        if (q.try_dequeue(val)) {
            // printf("output %d\n", val);
            i++;
        }
    }
    e = pump::time::get_clock_milliseconds();
    printf("use %lldms\n", e - b);
    thread1.join();
    thread11.join();

    std::thread thread2([&]() {
        for (int i = 0; i < cnt; i++) {
            qa.push(i);
        }
    });

    Sleep(1000);

    i = 0;
    int ii = -1;
    b = pump::time::get_clock_milliseconds();
    while (i < cnt) {
        int val;
        if (qa.pop(val)) {
            // printf("output %d\n", val);

            i++;
        }
    }
    e = pump::time::get_clock_milliseconds();
    printf("use %lldms\n", e - b);
    thread2.join();

    return 0;
}