#include "ws.h"

websocket::connection_sptr ws_conn;

void on_receive(websocket::connection *conn,
                const block_t *b,
                int32_t size,
                bool msg_end) {
    std::string data(b, size);
    std::string gbk = pump::utf8_to_gbk(data);
    printf("received: %s\n", gbk.c_str());

    conn->send_frame(b, size);
}

void on_error(websocket::connection *conn, const std::string &msg) {
    printf("disconnected\n");
    ws_conn.reset();
}

void on_new_connection(const std::string &path, websocket::connection_sptr conn) {
    printf("new ws connection\n");

    websocket::connection_callbacks cbs;
    cbs.frame_cb = pump_bind(&on_receive, conn.get(), _1, _2, _3);
    cbs.error_cb = pump_bind(&on_error, conn.get(), _1);
    conn->start(cbs);

    std::string msg = "hello world";
    std::string data = pump::gbk_to_utf8(msg);
    conn->send_frame(data.c_str(), (int32_t)data.size());

    ws_conn = conn;
}

void start_ws_server(pump::service *sv, const std::string &ip, int port) {
    pump::transport::address bind_address(ip, port);
    websocket::server_sptr server = websocket::server::create(bind_address);
    //pump::transport::tls_credentials xcerd = pump::transport::create_tls_credentials(false, false, cert, key);
    //websocket::server_sptr server = websocket::server::create(bind_address, xcerd);

    websocket::server_callbacks cbs;
    cbs.upgraded_cb = pump_bind(&on_new_connection, _1, _2);

    if (!server->start(sv, cbs))
        printf("ws server start error\n");
    else
        printf("ws server started\n");

    sv->wait_stopped();
}