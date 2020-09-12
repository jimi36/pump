#ifndef tcp_client_h
#define tcp_client_h

#include <pump/service.h>
#include <pump/time/timer.h>
#include <pump/transport/tcp_acceptor.h>
#include <pump/transport/tcp_dialer.h>
#include <pump/transport/tcp_transport.h>
#include <stdio.h>

namespace pump {
using namespace transport;
}

using namespace pump;

extern void start_tcp_server(const std::string &ip, uint16 port);

extern void start_tcp_client(const std::string &ip, uint16 port);

#endif