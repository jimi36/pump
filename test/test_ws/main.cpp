#include "ws.h"

int main(int argc, const char **argv) {
    if (argc < 2) {
        printf("usage: test_ws [s ip port] [c url]");
        return -1;
    }

    pump::init();

    pump::service *sv = new pump::service;
    sv->start();

    std::string type = argv[1];
    if (type == "s") {
        if (argc < 4) return -1;

        std::string ip = argv[2];
        int port = atoi(argv[3]);
        start_ws_server(sv, ip, port);
    } else if (type == "c") {
        if (argc < 3) return -1;

        std::string url = argv[2];
        start_ws_client(sv, url);
    }

    return 0;
}