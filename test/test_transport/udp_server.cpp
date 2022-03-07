#include "udp_transport_test.h"

static service *sv;

class my_udp_server {
  public:
    my_udp_server() {
        read_size_ = 0;
        last_report_time_ = ::time(0);
    }

    /*********************************************************************************
     * Udp read event callback
     ********************************************************************************/
    virtual void on_read_callback(base_transport *transp,
                                  const char *b,
                                  int32_t size,
                                  const address &from) {
        if (size > 0)
            read_size_ += size;

        uint64_t now = ::time(0);
        if (now > last_report_time_) {
            float32_t speed =
                (float32_t)read_size_ / 1024 / 1024 / (now - last_report_time_);
            printf("read speed %02f M/s\n", speed);

            read_size_ = 0;
            last_report_time_ = now;
        }
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
    int32_t read_size_;
    uint64_t last_report_time_;
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

    sv->wait_stopped();
}
