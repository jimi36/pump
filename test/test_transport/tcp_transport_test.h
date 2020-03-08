#ifndef tcp_client_h
#define tcp_client_h

#include <stdio.h>

#include <pump/times.h>
#include <pump/service.h>
#include <pump/transports.h>

using namespace pump;

extern void start_tcp_server(const std::string &ip, uint16 port);

extern void start_tcp_client(const std::string &ip, uint16 port);

#endif