#ifndef test_http_h
#define test_http_h

#include <pump/init.h>
#include <pump/protocol/http/client.h>
#include <pump/protocol/http/server.h>
#include <pump/protocol/http/uri.h>
#include <stdio.h>

#include <string>

using namespace pump::protocol;

void start_http_client(pump::service *sv, const std::vector<std::string> &urls);

void start_http_server(pump::service *sv, const std::string &ip, int port);

#endif