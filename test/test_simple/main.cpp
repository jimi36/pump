#include <pump/codec/base64.h>
#include <pump/service.h>

void func1(int *i) { (*i)++; }

int main(int argc, const char **argv) {
    int i3 = 0;
    pump_function<void()> fn3 = pump_bind(func1, &i3);
    // fn3 = pump_function<void()>();
    if (fn3) printf("1");

    int loop = 10000 * 100;

    int i2 = 0;
    std::function<void()> fn2 = std::bind(func1, &i2);
    auto b2 = pump::time::get_clock_milliseconds();
    for (int ii = 0; ii < loop; ii++) {
        fn2();
    }
    auto e2 = pump::time::get_clock_milliseconds();

    return 0;
}