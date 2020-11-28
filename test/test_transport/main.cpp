#include <pump/init.h>

#include "tcp_transport_test.h"
#include "tls_transport_test.h"
#include "udp_transport_test.h"

int main(int argc, const char **argv) {
    pump::init();

    if (argc < 5) return -1;

    std::string tag = argv[1];
    std::string tp = argv[2];
    std::string ip = argv[3];
    uint16_t port = atoi(argv[4]);

    if (tag == "tcp") {
        printf("start tcp test\n");

        std::thread server([=]() {
            if (tp == "s") start_tcp_server(ip, port);
        });

        std::thread client([=]() {
            if (tp == "c") start_tcp_client(ip, port);
        });

        server.join();
        client.join();
    }

    if (tag == "tls") {
        printf("start tls test\n");

        std::thread server([=]() {
            if (tp == "s") start_tls_server(ip, port, "cert.pem", "key.pem");
        });

        std::thread client([=]() {
            if (tp == "c") start_tls_client(ip, port);
        });

        server.join();
        client.join();
    }

    if (tag == "udp") {
        printf("start udp test\n");

        std::thread server([=]() {
            if (tp == "s") start_udp_server(ip, port);
        });

        std::thread client([=]() {
            if (tp == "c") start_udp_client(ip, port);
        });

        server.join();
        client.join();
    }

    pump::uninit();

    return 0;
}
