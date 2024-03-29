#include "udp_transport_test.h"

static service *sv;

class my_udp_client {
  public:
    /*********************************************************************************
     * Read event callback for udp
     ********************************************************************************/
    virtual void on_read_callback(base_transport *transp,
                                  const address &from,
                                  const char *b,
                                  int32_t size) {
        printf("read buffer %d\n", size);
    }

    /*********************************************************************************
     * Stopped event callback
     ********************************************************************************/
    virtual void on_stopped_callback(base_transport *transp) {}

    /*********************************************************************************
     * Disconnected event callback
     ********************************************************************************/
    virtual void on_disconnected_callback(base_transport *transp) {}
};

void send(udp_transport_sptr transport, const std::string &ip, uint16_t port) {
    char buf[4096];
    address addr(ip, port);
    transport->send(buf, 4096, addr);
}

static std::shared_ptr<my_udp_client> udp_client;

void start_udp_client(const std::string &ip, uint16_t port) {
    sv = new service;
    sv->start();

    udp_client.reset(new my_udp_client);

    address localaddr("0.0.0.0", 0);
    udp_transport_sptr transport = udp_transport::create(localaddr);

    pump::transport_callbacks cbs;
    cbs.read_from_cb = pump_bind(&my_udp_client::on_read_callback,
                                 udp_client.get(),
                                 transport.get(),
                                 _1,
                                 _2,
                                 _3);
    cbs.stopped_cb = pump_bind(&my_udp_client::on_stopped_callback,
                               udp_client.get(),
                               transport.get());

    if (transport->start(sv, read_mode_loop, cbs) != 0) {
        printf("udp client start error\n");
        return;
    }

    transport->async_read();

    send(transport, ip, port);

    sv->wait_stopped();
}
