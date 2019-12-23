#ifndef tls_client_h
#define tls_client_h

#include <stdio.h>

#include <pump/time.h>
#include <pump/service.h>
#include <pump/transport.h>

using namespace pump;

extern void start_tls_server(const std::string &ip, uint16 port, const std::string &cert_file, const std::string &key_file);

extern void start_tls_client(const std::string &ip, uint16 port);

#endif