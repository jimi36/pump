#include "http.h"

#include <regex>

int main(int argc, const char **argv) {
    pump::init();

    pump::service *sv = new pump::service;
    sv->start();

    std::string type = argv[1];
    if (type == "s") {
        if (argc < 4)
            return -1;

        std::string ip = argv[2];
        int port = atoi(argv[3]);
        start_http_server(sv, ip, port);
    } else if (type == "c") {
        if (argc < 3)
            return -1;

        std::vector<std::string> urls;
        for (int i = 2; i < argc; i++) {
            urls.push_back(argv[i]);
        }
        start_http_client(sv, urls);
    }

    return 0;
}