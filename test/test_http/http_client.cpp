#include <iostream>

#include "http.h"

int loop = 1;

void start_http_client(pump::service *sv, const std::vector<std::string> &urls) {
    http::client_sptr cli = http::client::create(sv);

    for (int ii = 0; ii < (int)urls.size(); ii++) {
        http::request_sptr req(new http::request);
        req->set_url(urls[ii]);
        req->set_method(http::METHOD_GET);
        req->set_http_version(http::VERSION_11);
        req->set_head("Host", req->get_uri()->get_host());
        req->set_head("User-Agent", "PostmanRuntime/7.24.0");
        req->set_head("Accept", "*/*");
        req->set_head("Connection", "keep-alive");

        int succ = 0;
        auto beg = pump::time::get_clock_milliseconds();
        for (int i = 0; i < loop; i++) {
            http::response_sptr resp = cli->request(req);
            if (!resp) {
                printf("false\n");
                continue;
            }

            if (resp->get_status_code() == 200) succ++;

            std::string html = pump::utf8_to_gbk(resp->get_content()->data());
            //std::cout << html.size() <<std::endl;
        }
        auto end = pump::time::get_clock_milliseconds();
        printf("request used %dms succ %d\n", int32_t(end - beg), succ);
    }

    sv->wait_stopped();
}