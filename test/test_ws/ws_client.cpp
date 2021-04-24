#include "ws.h"

void on_started(websocket::client *cli) {
    if (!cli->send("123", 3))
        PUMP_ASSERT(false);
}

void on_error(websocket::client *cli, const std::string &msg) {
    printf("ws client erorr %s\n", msg.c_str());
}

void on_data(websocket::client *cli,
             const block_t *b,
             uint32_t size,
             bool msg_end) {
    std::string data(b, size);
    std::string msg = pump::utf8_to_gbk(data);
    printf("dara %s raw_msg %s\n", data.c_str(), msg.c_str());
}

void start_ws_client(pump::service *sv, const std::string &url) {
    std::map<std::string, std::string> headers;
    websocket::client_sptr cli = websocket::client::create(url, headers);

    websocket::client_callbacks cbs;
    cbs.started_cb = pump_bind(&on_started, cli.get());
    cbs.error_cb = pump_bind(&on_error, cli.get(), _1);
    cbs.data_cb = pump_bind(&on_data, cli.get(), _1, _2, _3);
    if (!cli->start(sv, cbs))
        printf("websocket client start error\n");
    else
        printf("websocket client startd\n");

    //cli->send("123", 3);

    sv->wait_stopped();
}