#ifndef test_http_h
#define test_http_h

#include <string>

#include <pump/init.h>
#include <pump/proto/http/client.h>
#include <pump/proto/http/server.h>

using namespace pump::proto;

void start_ws_client(pump::service *sv, const std::string &url);

void start_ws_server(pump::service *sv, const std::string &ip, int port);

#endif