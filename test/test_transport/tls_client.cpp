#include "tls_transport_test.h"

static service *sv;

static uint16_t server_port;
static std::string server_ip;

static int count = 1;
static int send_loop = 1;
static int send_pocket_size = 1024 * 4;
// static int send_pocket_count = 1024 * 100;
static int send_pocket_count = -1;

class my_tls_dialer;
static std::mutex dial_mx;
static std::map<my_tls_dialer *, std::shared_ptr<my_tls_dialer>> my_dialers;

void start_once_tls_dialer();

class my_tls_dialer : public std::enable_shared_from_this<my_tls_dialer> {
  public:
    my_tls_dialer() {
        read_size_ = 0;
        all_read_size_ = 0;
        read_pocket_size_ = 0;
        send_data_.resize(send_pocket_size);
    }

    /*********************************************************************************
     * Tls dialed event callback
     ********************************************************************************/
    void on_dialed_callback(base_transport_sptr &transp, bool succ) {
        if (!succ) {
            printf("tls cleint dialed error\n");
            return;
        }

        transport_ = std::static_pointer_cast<tls_transport>(transp);

        pump::transport_callbacks cbs;
        cbs.read_cb = pump_bind(
            &my_tls_dialer::on_read_callback,
            this,
            transp.get(),
            _1,
            _2);
        cbs.stopped_cb = pump_bind(
            &my_tls_dialer::on_stopped_callback,
            this,
            transp.get());
        cbs.disconnected_cb = pump_bind(
            &my_tls_dialer::on_disconnected_callback,
            this,
            transp.get());

        if (transport_->start(sv, read_mode_loop, cbs) != 0)
            return;

        transport_->async_read();

        printf("tls client dialed\n");

        for (int i = 0; i < send_loop; i++) {
            send_data();
        }
    }

    /*********************************************************************************
     * Tls dialed error event callback
     ********************************************************************************/
    void on_dialed_error_callback() {
        printf("tls client transport dialed error\n");
    }

    /*********************************************************************************
     * Tls dialed timeout event callback
     ********************************************************************************/
    void on_dialed_timeout_callback() {
        printf("tls client transport dialed timeout\n");
    }

    /*********************************************************************************
     * Stopped dial event callback
     ********************************************************************************/
    void on_stopped_dialing_callback() {
        printf("tls client dial stopped\n");
    }

    /*********************************************************************************
     * Tls read event callback
     ********************************************************************************/
    void on_read_callback(base_transport *transp, const char *b, int32_t size) {
        read_size_ += size;
        all_read_size_ += size;
        read_pocket_size_ += size;

        if (read_pocket_size_ >= send_pocket_size) {
            read_pocket_size_ -= send_pocket_size;
            send_data();
        }

        // transp->continue_read();
    }

    /*********************************************************************************
     * Tls disconnected event callback
     ********************************************************************************/
    void on_disconnected_callback(base_transport *transp) {
        printf("client tls transport disconnected\n");
        dial_mx.lock();
        my_dialers.erase(this);
        dial_mx.unlock();
    }

    /*********************************************************************************
     * Tls stopped event callback
     ********************************************************************************/
    void on_stopped_callback(base_transport *transp) {
        printf("client tls transport stopped\n");
        dial_mx.lock();
        if (my_dialers.erase(this) != 1) {
            printf("erase dialer error\n");
        }
        start_once_tls_dialer();
        dial_mx.unlock();
    }

    void send_data() {
        if (transport_->send(send_data_.data(), (int32_t)send_data_.size()) != 0)
            printf("send data error\n");
    }

    void set_dialer(tls_dialer_sptr dialer) {
        dialer_ = dialer;
    }

  public:
    volatile int32_t read_size_;
    volatile int32_t read_pocket_size_;
    volatile int64_t last_report_time_;
    volatile int32_t all_read_size_;

    std::string send_data_;

    tls_dialer_sptr dialer_;
    tls_transport_sptr transport_;
};

class tls_time_report {
  public:
    static void on_timer_timeout() {
        int read_size = 0;

        dial_mx.lock();
        auto b = my_dialers.begin();
        for (; b != my_dialers.end(); b++) {
            read_size += b->second->read_size_;
            b->second->read_size_ = 0;

            if (send_pocket_count > 0 &&
                b->second->all_read_size_ >=
                    send_pocket_count * send_pocket_size &&
                b->second->transport_->is_started()) {
                b->second->transport_->stop();
            }
        }
        dial_mx.unlock();

        printf(
            "client read speed is %fMB/s at %d\n",
            (double)read_size / 1024 / 1024 / 1,
            (int32_t)::time(0));
    }
};

void start_once_tls_dialer() {
    address bind_address("0.0.0.0", 0);
    address peer_address(server_ip, server_port);
    tls_dialer_sptr dialer = tls_dialer::create(bind_address, peer_address, 1000);

    std::shared_ptr<my_tls_dialer> my_dialer(new my_tls_dialer);
    my_dialer->set_dialer(dialer);

    pump::dialer_callbacks cbs;
    cbs.dialed_cb = pump_bind(
        &my_tls_dialer::on_dialed_callback,
        my_dialer.get(),
        _1,
        _2);
    cbs.stopped_cb = pump_bind(
        &my_tls_dialer::on_stopped_dialing_callback,
        my_dialer.get());
    cbs.timeouted_cb = pump_bind(
        &my_tls_dialer::on_dialed_timeout_callback,
        my_dialer.get());

    if (dialer->start(sv, cbs) != 0) {
        printf("tcp dialer start error\n");
        return;
    }

    my_dialers[my_dialer.get()] = my_dialer;
}

void start_tls_client(
    const std::string &ip,
    uint16_t port,
    int32_t conn_count) {
    server_ip = ip;
    server_port = port;

    count = conn_count;

    sv = new service;
    sv->start();

    for (int i = 0; i < count; i++) {
        start_once_tls_dialer();
    }

    time::timer_callback cb = pump_bind(&tls_time_report::on_timer_timeout);
    time::timer_sptr t = time::timer::create(1000000000, cb, true);
    sv->start_timer(t);

    sv->wait_stopped();
}
