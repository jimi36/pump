#include <stdio.h>
#include <pump/toolkit/freelock.h>
#include "concurrentqueue.h"

class Test : public pump::toolkit::noncopyable {
  public:
    Test() {
        printf("Test()\n");
    }

    Test(const Test &t) {
        printf("Test(const Test &)\n");
    }

    ~Test() {
        printf("~Test()\n");
    }

    Test& operator=(const Test& t) {
        printf("Test& operator=(Test& t)\n");
        return *this;
    }
};

int main(int argc, const char **argv) {
    
    pump::toolkit::freelock_list<Test> tlist(2);

    Test t;
    for (int i = 0; i < 4; i++) {
        tlist.push(t);
    }
    
    int i;
    while (tlist.pop(t)) {
        printf("%d\n", i);
    }

    /*
    moodycamel::ConcurrentQueue<Test> tlist;

    Test t;
    for (int i = 0; i < 4; i++) {
        tlist.enqueue(t);
    }
    */
    return 0;
}
