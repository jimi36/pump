#ifndef tls_client_h
#define tls_client_h

#include <pump/service.h>
#include <pump/time/timer.h>
#include <pump/transport/tls_acceptor.h>
#include <pump/transport/tls_dialer.h>
#include <pump/transport/tls_transport.h>
#include <stdio.h>

namespace pump {
using namespace transport;
}

using namespace pump;

extern void start_tls_server(
    const std::string &ip,
    uint16_t port,
    const std::string &cert_file,
    const std::string &key_file);

extern void start_tls_client(
    const std::string &ip,
    uint16_t port,
    int32_t conn_count);

#endif