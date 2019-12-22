#ifndef udp_server_h
#define udp_server_h

#include <stdio.h>

#include <librabbit/time.h>
#include <librabbit/service.h>
#include <librabbit/transport.h>

using namespace librabbit;

extern void start_udp_server(const std::string &ip, uint16 port);

extern void start_udp_client(const std::string &ip, uint16 port);

#endif