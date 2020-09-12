#include "ws.h"

websocket::connection_sptr ws_conn;

void on_receive(websocket::connection_ptr conn, const char *b,
                unsigned int size, bool msg_end) {
    std::string data(b, size);
    std::string gbk = pump::utf8_to_gbk(data);
    printf("received: %s\n", gbk.c_str());

    conn->send(b, size);
}

void on_error(websocket::connection_ptr conn, const std::string &msg) {
    printf("disconnected\n");
    ws_conn.reset();
}

void on_new_connection(websocket::connection_sptr conn) {
    printf("new ws connection\n");

    websocket::connection_callbacks cbs;
    cbs.data_cb = pump_bind(&on_receive, conn.get(), _1, _2, _3);
    cbs.error_cb = pump_bind(&on_error, conn.get(), _1);
    conn->start(cbs);

    std::string msg = "hello world";
    std::string data = pump::gbk_to_utf8(msg);
    conn->send(data.c_str(), data.size());

    ws_conn = conn;
}

void start_ws_server(pump::service_ptr sv, const std::string &ip, int port) {
    websocket::server_sptr server = websocket::server::create_instance();
    server->append_route("/", pump_bind(&on_new_connection, _1));

    pump::transport::address bind_address(ip, port);

    std::map<std::string, std::string> headers;

    if (!server->start(sv, bind_address, headers))
        // if (!server->start(sv, "cert.pem", "key.pem", bind_address, headers))
        printf("ws server start error\n");
    else
        printf("ws server started\n");

    sv->wait_stopped();
}