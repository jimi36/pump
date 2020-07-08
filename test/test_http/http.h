#ifndef test_http_h
#define test_http_h

#include <string>
#include <stdio.h>

#include <pump/init.h>
#include <pump/protocol/http/uri.h>
#include <pump/protocol/http/client.h>
#include <pump/protocol/http/server.h>

using namespace pump::protocol;

void start_http_client(pump::service_ptr sv, const std::string &url);

void start_http_server(pump::service_ptr sv, const std::string &ip, int port);

#endif