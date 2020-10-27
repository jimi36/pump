#include <iostream>

#include "http.h"

int loop = 100;

void start_http_client(pump::service_ptr sv, const std::string &url) {
    http::client_sptr cli = http::client::create(sv);

    http::request_sptr req(new http::request);
    req->set_url(url);
    req->set_method(http::METHOD_GET);
    req->set_http_version(http::VERSION_11);
    req->get_header()->set("Host", req->get_uri()->get_host());
    req->get_header()->set("User-Agent", "PostmanRuntime/7.24.0");
    req->get_header()->set("Accept", "*/*");
    req->get_header()->set("Connection", "keep-alive");

    int succ = 0;
    auto beg = pump::time::get_clock_milliseconds();
    for (int i = 0; i < loop; i++) {
        http::response_sptr resp = cli->request(req);
        if (!resp) {
            printf("false\n");
            continue;
        }

        if (resp->get_status_code() == 200) succ++;

        // std::string html = pump::utf8_to_gbk(resp->get_content()->data());
        // std::cout << html.size()<<std::endl;
    }
    auto end = pump::time::get_clock_milliseconds();
    printf("request used %llums succ %d\n", end - beg, succ);

    sv->wait_stopped();
}