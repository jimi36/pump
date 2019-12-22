#ifndef tcp_client_h
#define tcp_client_h

#include <stdio.h>

#include <librabbit/time.h>
#include <librabbit/service.h>
#include <librabbit/transport.h>

using namespace librabbit;

extern void start_tcp_server(const std::string &ip, uint16 port);

extern void start_tcp_client(const std::string &ip, uint16 port);

#endif