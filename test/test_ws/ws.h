#ifndef test_http_h
#define test_http_h

#include <string>
#include <stdio.h>

#include <pump/init.h>
#include <pump/protocol/websocket/client.h>
#include <pump/protocol/websocket/server.h>

using namespace pump::protocol;

void start_ws_client(pump::service_ptr sv, const std::string &url);

void start_ws_server(pump::service_ptr sv, const std::string &ip, int port);

#endif