#include "tcp_transport_test.h"

static service *sv;

static uint32_t send_pocket_size = 1024 * 4;

struct transport_context {
    transport_context(tcp_transport_sptr t) {
        transport = t;
        all_read_size = 0;
        read_size = 0;
        read_pocket_size = 0;
        last_report_time = (int32_t)::time(0);
        idx = (int32_t)t->get_fd();
    }

    tcp_transport_sptr transport;
    uint64_t all_read_size;
    uint32_t read_size;
    uint32_t read_pocket_size;
    int32_t last_report_time;
    int32_t idx;
};

class my_tcp_acceptor : public std::enable_shared_from_this<my_tcp_acceptor> {
  public:
    my_tcp_acceptor() {
        send_data_.resize(send_pocket_size);
    }

    /*********************************************************************************
     * Tcp accepted event callback
     ********************************************************************************/
    void on_accepted_callback(base_transport_sptr &transp) {
        tcp_transport_sptr transport =
            std::static_pointer_cast<tcp_transport>(transp);
        auto tctx = new transport_context(transport);
        transport->set_context(tctx);

        pump::transport_callbacks cbs;
        cbs.read_cb = pump_bind(
            &my_tcp_acceptor::on_read_callback,
            this,
            transp.get(),
            _1,
            _2);
        cbs.stopped_cb = pump_bind(
            &my_tcp_acceptor::on_stopped_callback,
            this,
            transp.get());
        cbs.disconnected_cb = pump_bind(
            &my_tcp_acceptor::on_disconnected_callback,
            this,
            transp.get());
        cbs.sent_cb = pump_bind(&my_tcp_acceptor::on_sent_callback, this, _1);

        if (transport->start(sv, read_mode_once, cbs) == 0) {
            std::lock_guard<std::mutex> lock(mx_);
            transports_[transp.get()] = tctx;
        }

        printf("server tcp transport accepted\n");
    }

    /*********************************************************************************
     * Stopped accepting event callback
     ********************************************************************************/
    void on_stopped_accepting_callback() {}

    /*********************************************************************************
     * Tcp read event callback
     ********************************************************************************/
    void on_read_callback(base_transport *transp, const char *b, int32_t size) {
        transport_context *ctx = (transport_context *)transp->get_context();

        ctx->read_size += size;
        ctx->all_read_size += size;
        ctx->read_pocket_size += size;

        if (ctx->read_pocket_size >= send_pocket_size) {
            ctx->read_pocket_size -= send_pocket_size;
            send_data(transp);
        }

        transp->continue_read();
    }

    void on_sent_callback(toolkit::io_buffer *iob) {
        if (iob == nullptr) {
            printf("iob is nullptr\n");
            return;
        }
        std::lock_guard<std::mutex> lock(buf_mx_);
        iobs_.push_back(iob);
        iob->refer();
    }

    /*********************************************************************************
     * Tcp disconnected event callback
     ********************************************************************************/
    void on_disconnected_callback(base_transport *transp) {
        std::lock_guard<std::mutex> lock(mx_);
        auto it = transports_.find(transp);
        if (it != transports_.end()) {
            printf("tcp transport disconnected all read size %fMB\n",
                   (double)it->second->all_read_size / 1024 / 1024);
            printf("tcp transport disconnected all read pocket %d\n",
                   (int32_t)(it->second->all_read_size / 4096));
            delete it->second;
            transports_.erase(it);
        }
    }

    /*********************************************************************************
     * Tcp stopped event callback
     ********************************************************************************/
    void on_stopped_callback(base_transport *transp) {
        std::lock_guard<std::mutex> lock(mx_);
        auto it = transports_.find(transp);
        if (it != transports_.end()) {
            printf("server tcp transport stopped\n");
            delete it->second;
        }
    }

    void send_data(base_transport *transport) {
        std::lock_guard<std::mutex> lock(buf_mx_);
        if (iobs_.empty()) {
            transport->send(send_data_.data(), (int32_t)send_data_.size());
        } else {
            auto iob = iobs_.front();
            iobs_.pop_front();

            iob->write(char(0), send_pocket_size);
            transport->send(iob);
            iob->unrefer();
        }
    }

  private:
    std::string send_data_;

    std::mutex mx_;
    std::map<void *, transport_context *> transports_;

    std::mutex buf_mx_;
    std::list<toolkit::io_buffer *> iobs_;
};

void start_tcp_server(const std::string &ip, uint16_t port) {
    sv = new service;
    sv->start();

    my_tcp_acceptor *my_acceptor = new my_tcp_acceptor;

    pump::acceptor_callbacks cbs;
    cbs.accepted_cb =
        pump_bind(&my_tcp_acceptor::on_accepted_callback, my_acceptor, _1);
    cbs.stopped_cb =
        pump_bind(&my_tcp_acceptor::on_stopped_accepting_callback, my_acceptor);

    address listen_address(ip, port);
    tcp_acceptor_sptr acceptor = tcp_acceptor::create(listen_address);
    if (acceptor->start(sv, cbs) != 0) {
        printf("tcp acceptor start error\n");
    }

    sv->wait_stopped();
}
