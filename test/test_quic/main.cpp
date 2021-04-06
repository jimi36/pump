#include <stdio.h>
#include <pump/init.h>

#include "handshaker.h"

int main(int argc, const char **argv) {
    
    pump::init();

    test_handshaker();

    pump::uninit();

    return 0;
}