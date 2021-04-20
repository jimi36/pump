#include "handshaker.h"

#include <pump/service.h>
#include <pump/protocol/quic/tls/client.h>
#include <pump/protocol/quic/tls/server.h>

using namespace pump;
using namespace protocol::quic::tls;

client_handshaker *ch = nullptr;
server_handshaker *sh = nullptr;

void server_read_callback(const std::string &data) {
    handshake_message *msg = new_handshake_message((message_type)data[0]);
    int32_t ret = unpack_handshake_message((const uint8_t*)data.data(), (int32_t)data.size(), msg);
    if (ret != (int32_t)data.size()) {
        printf("server_read_callback unpack_handshake_message failed %d\n", ret);
    } else {
        if (!sh->handshake(msg)) {
            printf("server_read_callback server handshake failed\n");
        }
    }
    delete_handshake_message(msg);
}

void server_finished_callback(const connection_session &session) {
    printf("server_finished_callback \n");
}

void client_read_callback(const std::string &data) {
    handshake_message *msg = new_handshake_message((message_type)data[0]);
    int32_t ret = unpack_handshake_message((const uint8_t*)data.data(), (int32_t)data.size(), msg);
    if (ret != (int32_t)data.size()) {
        printf("client_read_callback unpack_handshake_message failed %d\n", ret);
        return;
    } else {
        if (!ch->handshake(msg)) {
            printf("client_read_callback client handshake failed\n");
        }
    }
    delete_handshake_message(msg);
}

void client_finished_callback(const connection_session &session) {
    printf("client_finished_callback \n");
}

void test_handshaker() {
    service *sv = new pump::service;
    sv->start();

    sh = new server_handshaker();
    sh->set_callbacks(pump_bind(client_read_callback, _1), pump_bind(server_finished_callback, _1));

    config scfg;
    //scfg.cert = cert;
    scfg.application_protocol = "test";
    scfg.server_name = "local";
    sh->handshake(scfg);

    ch = new client_handshaker();
    ch->set_callbacks(pump_bind(server_read_callback, _1), pump_bind(client_finished_callback, _1));

    config ccfg;
    ccfg.application_protocol = "test";
    ccfg.server_name = "local";
    ch->handshake(ccfg);

    sv->wait_stopped();
}