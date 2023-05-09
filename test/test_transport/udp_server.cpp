#include "udp_transport_test.h"

static service *sv;

class my_udp_server {
  public:
    my_udp_server() {
    }

    /*********************************************************************************
     * Udp read event callback
     ********************************************************************************/
    virtual void on_read_callback(base_transport *transp,
                                  const address &from,
                                  const char *b,
                                  int32_t size) {
        printf("read buffer %d\n", size);
        transp->send(b, size, from);

    }

    /*********************************************************************************
     * Sent event callback
     ********************************************************************************/
    virtual void on_sent_callback(base_transport *transp) {}

    /*********************************************************************************
     * Stopped event callback
     ********************************************************************************/
    virtual void on_stopped_callback(base_transport *transp) {}

    /*********************************************************************************
     * Disconnected event callback
     ********************************************************************************/
    virtual void on_disconnected_callback(base_transport *transp) {}

  private:
};

static std::shared_ptr<my_udp_server> udp_server;

void start_udp_server(const std::string &ip, uint16_t port) {
    sv = new service;
    sv->start();

    udp_server.reset(new my_udp_server);

    address localaddr(ip, port);
    udp_transport_sptr transport = udp_transport::create(localaddr);

    transport_callbacks cbs;
    cbs.read_from_cb = pump_bind(&my_udp_server::on_read_callback,
                                 udp_server.get(),
                                 transport.get(),
                                 _1,
                                 _2,
                                 _3);
    cbs.stopped_cb = pump_bind(&my_udp_server::on_stopped_callback,
                               udp_server.get(),
                               transport.get());

    if (transport->start(sv, read_mode_loop, cbs) != 0) {
        printf("udp server start error\n");
    }

    transport->async_read();

    sv->wait_stopped();
}
