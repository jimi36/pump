#include "ws.h"

static void on_receive(
    const block_t *b,
    int32_t size,
    bool msg_end) {
    std::string data(b, size);
    std::string gbk = pump::utf8_to_gbk(data);
    printf("received: %s\n", gbk.c_str());
}

static void on_error(const std::string &msg) {
    printf("disconnected\n");
}

void start_ws_client(pump::service *sv, const std::string &url) {
    http::client_sptr cli = http::client::create(sv);

    auto conn = cli->open_websocket(url);
    if (!conn) {
        printf("websocket client open error\n");
        return;
    }

    http::websocket_callbacks cbs;
    cbs.frame_cb = pump_bind(&on_receive, _1, _2, _3);
    cbs.error_cb = pump_bind(&on_error, _1);
    if (!conn->start_websocket(cbs)) {
        conn->stop();
        return;
    }

    conn->send("123", 3);

    sv->wait_stopped();
}