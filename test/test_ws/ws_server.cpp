#include "ws.h"

http::connection_sptr ws_conn;

static void on_receive(
    const block_t *b,
    int32_t size,
    bool msg_end) {
    std::string data(b, size);
    std::string gbk = pump::utf8_to_gbk(data);
    printf("received: %s %s\n", data.c_str(), gbk.c_str());

    if (!ws_conn->send(b, size)) {
        printf("websocket send failed\n");
    }
}

static void on_error(const std::string &msg) {
    printf("websocket %s\n", msg.c_str());
    ws_conn.reset();
}

void on_new_request(http::connection_wptr &wconn, http::request_sptr &&req) {
    static std::string data = "hello world 1!!!";

    auto conn = wconn.lock();

    if (!http::upgrade_to_websocket(conn.get(), req)) {
        printf("websocket request failed\n");
        conn->stop();
        return;
    }

    ws_conn = conn;

    http::websocket_callbacks cbs;
    cbs.frame_cb = pump_bind(&on_receive, _1, _2, _3);
    cbs.error_cb = pump_bind(&on_error, _1);
    if (!ws_conn->start_websocket(cbs)) {
        printf("websocket start failed\n");
        conn->stop();
        return;
    }

    printf("websocket connected\n");
}

void on_stopped() {

}

void start_ws_server(pump::service *sv, const std::string &ip, int port) {
    pump::transport::address bind_address(ip, port);

    http::server_callbacks cbs;
    cbs.request_cb = pump_bind(&on_new_request, _1, _2);
    cbs.stopped_cb = pump_bind(&on_stopped);

    auto svr = http::server::create();
    if (!svr->start(sv, bind_address, cbs)) {
        printf("http server start error\n");
    } else {
        printf("http server started\n");
    }

    sv->wait_stopped();
}