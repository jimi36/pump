#include "tcp_transport_test.h"

static int count = 1;
static int send_loop = 1;
static int send_pocket_size = 1024 * 4;
// static int send_pocket_count = 1024 * 100;
static int send_pocket_count = -1;

static service *sv;

static uint16_t server_port;
static std::string server_ip;

class my_tcp_dialer;
static std::mutex dial_mx;
static std::map<my_tcp_dialer *, std::shared_ptr<my_tcp_dialer>> my_dialers;

void start_once_dialer();

class my_tcp_dialer : public std::enable_shared_from_this<my_tcp_dialer> {
  public:
    my_tcp_dialer() {
        read_size_ = 0;
        read_pocket_size_ = 0;
        all_read_size_ = 0;
        last_report_time_ = 0;
        send_data_.resize(send_pocket_size);
        left_send_pocket_count_ = send_pocket_count;
    }

    virtual ~my_tcp_dialer() {}

    /*********************************************************************************
     * Tcp dialed event callback
     ********************************************************************************/
    void on_dialed_callback(pump::base_transport_sptr &transp, bool succ) {
        if (!succ) {
            printf("tcp client dialed error\n");
            return;
        }

        pump::transport_callbacks cbs;
        cbs.read_cb = pump_bind(&my_tcp_dialer::on_read_callback,
                                this,
                                transp.get(),
                                _1,
                                _2);
        cbs.stopped_cb =
            pump_bind(&my_tcp_dialer::on_stopped_callback, this, transp.get());
        cbs.disconnected_cb =
            pump_bind(&my_tcp_dialer::on_disconnected_callback,
                      this,
                      transp.get());

        transport_ = std::static_pointer_cast<pump::tcp_transport>(transp);
        if (transport_->start(sv, READ_MODE_ONCE, cbs) != 0) {
            return;
        }

        printf("tcp client dialed\n");

        for (int i = 0; i < send_loop; i++) {
            send_data();
        }
    }

    /*********************************************************************************
     * Tcp dialed timeout event callback
     ********************************************************************************/
    void on_dialed_timeout_callback() {
        printf("tcp client dial timeout\n");
    }

    /*********************************************************************************
     * Stopped dial event callback
     ********************************************************************************/
    void on_stopped_dialing_callback() {
        printf("tcp client dial stopped\n");
    }

    /*********************************************************************************
     * Tcp read event callback
     ********************************************************************************/
    void on_read_callback(base_transport *transp, const char *b, int32_t size) {
        read_size_ += size;
        all_read_size_ += size;
        read_pocket_size_ += size;

        if (read_pocket_size_ >= send_pocket_size) {
            read_pocket_size_ -= send_pocket_size;
            send_data();
        }

        transp->continue_read();
    }

    /*********************************************************************************
     * Tcp disconnected event callback
     ********************************************************************************/
    void on_disconnected_callback(base_transport *transp) {
        printf("client tcp transport disconnected read raw_msg %d\n",
               all_read_size_ / 4096);
        dial_mx.lock();
        my_dialers.erase(this);
        dial_mx.unlock();
    }

    /*********************************************************************************
     * Tcp stopped event callback
     ********************************************************************************/
    void on_stopped_callback(base_transport *transp) {
        printf("client tcp transport stopped read raw_msg %d\n",
               all_read_size_ / 4096);
        dial_mx.lock();
        if (my_dialers.erase(this) != 1) {
            printf("erase dialer error\n");
        }
        start_once_dialer();
        dial_mx.unlock();
    }

    void set_dialer(tcp_dialer_sptr d) {
        dialer_ = d;
    }

    inline bool send_data() {
        if (!transport_) {
            return false;
        }
        if (transport_->send(send_data_.data(), (int32_t)send_data_.size()) !=
            0) {
            printf("send error\n");
            return false;
        }

        return true;
    }

  public:
    volatile int32_t read_size_;
    volatile int32_t read_pocket_size_;
    volatile int32_t all_read_size_;

    volatile int32_t left_send_pocket_count_;

    int64_t last_report_time_;

    std::string send_data_;

    tcp_dialer_sptr dialer_;
    tcp_transport_sptr transport_;
};

void start_once_dialer() {
    address bind_address("0.0.0.0", 0);
    address peer_address(server_ip, server_port);
    tcp_dialer_sptr dialer =
        tcp_dialer::create(bind_address, peer_address, 1000);

    std::shared_ptr<my_tcp_dialer> my_dialer(new my_tcp_dialer);
    my_dialer->set_dialer(dialer);

    pump::dialer_callbacks cbs;
    cbs.dialed_cb =
        pump_bind(&my_tcp_dialer::on_dialed_callback, my_dialer.get(), _1, _2);
    cbs.stopped_cb =
        pump_bind(&my_tcp_dialer::on_stopped_dialing_callback, my_dialer.get());
    cbs.timeouted_cb =
        pump_bind(&my_tcp_dialer::on_dialed_timeout_callback, my_dialer.get());

    if (dialer->start(sv, cbs) != 0) {
        printf("tcp dialer start error\n");
        return;
    }

    my_dialers[my_dialer.get()] = my_dialer;
}

class time_report {
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

        printf("client read speed is %fMB/s at %d\n",
               (double)read_size / 1024 / 1024 / 1,
               (int32_t)::time(0));
    }
};

void start_tcp_client(const std::string &ip,
                      uint16_t port,
                      int32_t conn_count) {
    server_ip = ip;
    server_port = port;

    count = conn_count;

    sv = new service;
    sv->start();

    dial_mx.lock();
    for (int i = 0; i < count; i++) {
        start_once_dialer();
    }
    dial_mx.unlock();

    time::timer_callback cb = pump_bind(&time_report::on_timer_timeout);
    time::timer_sptr t = time::timer::create(1000 * 1, cb, true);
    sv->start_timer(t);

    sv->wait_stopped();
}
