#include "tls_transport_test.h"

static service *sv;

static int count = 1;
static int send_loop = 64;
static int send_pocket_size = 1024 * 4;

class my_tls_dialer : public std::enable_shared_from_this<my_tls_dialer> {
  public:
    my_tls_dialer() {
        read_size_ = 0;
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
        cbs.read_cb =
            pump_bind(&my_tls_dialer::on_read_callback, this, transp.get(), _1, _2);
        cbs.stopped_cb =
            pump_bind(&my_tls_dialer::on_stopped_callback, this, transp.get());
        cbs.disconnected_cb =
            pump_bind(&my_tls_dialer::on_disconnected_callback, this, transp.get());

        if (transport_->start(sv, 0, cbs) != 0)
            return;

        transport_->read_for_loop();

        printf("tls client dialed %d\n", transp->get_fd());

        for (int i = 0; i < send_loop; i++) {
            send_data();
        }

        printf("tls client dialed %d sent\n", transp->get_fd());
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
    void on_read_callback(base_transport_ptr transp, c_block_ptr b, int32 size) {
        read_size_ += size;
        read_pocket_size_ += size;

        while (read_pocket_size_ >= send_pocket_size) {
            read_pocket_size_ -= send_pocket_size;
            send_data();
        }
    }

    /*********************************************************************************
     * Tls disconnected event callback
     ********************************************************************************/
    void on_disconnected_callback(base_transport_ptr transp) {
        printf("client tls transport disconnected\n");
        transport_.reset();
    }

    /*********************************************************************************
     * Tls stopped event callback
     ********************************************************************************/
    void on_stopped_callback(base_transport_ptr transp) {
        printf("client tls transport stopped\n");
    }

    void send_data() {
        if (transport_->send(send_data_.data(), send_data_.size()) != 0)
            printf("send data error\n");
    }

    void set_dialer(tls_dialer_sptr dialer) {
        dialer_ = dialer;
    }

  public:
    int32 read_size_;
    int32 read_pocket_size_;
    int64 last_report_time_;

    std::string send_data_;

    tls_transport_sptr transport_;

    tls_dialer_sptr dialer_;
};

static std::vector<std::shared_ptr<my_tls_dialer>> my_dialers;

class tls_time_report {
  public:
    static void on_timer_timeout() {
        int read_size = 0;
        for (int i = 0; i < count; i++) {
            read_size += my_dialers[i]->read_size_;
            my_dialers[i]->read_size_ = 0;
        }
        printf("client read speed is %fMB/s\n", (float)read_size / 1024 / 1024);
    }
};

void start_tls_client(const std::string &ip, uint16 port) {
    sv = new service;
    sv->start();

    for (int i = 0; i < count; i++) {
        address bind_address("0.0.0.0", 0);
        address remote_address(ip, port);
        tls_dialer_sptr dialer =
            tls_dialer::create(bind_address, remote_address);

        std::shared_ptr<my_tls_dialer> my_dialer(new my_tls_dialer);
        my_dialer->set_dialer(dialer);

        my_dialers.push_back(my_dialer);

        pump::dialer_callbacks cbs;
        cbs.dialed_cb =
            pump_bind(&my_tls_dialer::on_dialed_callback, my_dialer.get(), _1, _2);
        cbs.stopped_cb =
            pump_bind(&my_tls_dialer::on_stopped_dialing_callback, my_dialer.get());
        cbs.timeout_cb =
            pump_bind(&my_tls_dialer::on_dialed_timeout_callback, my_dialer.get());

        if (dialer->start(sv, cbs) != 0) {
            printf("tls dialer start error\n");
        }
    }

    time::timer_callback cb = pump_bind(&tls_time_report::on_timer_timeout);
    time::timer_sptr t = time::timer::create(1000, cb, true);
    sv->start_timer(t);

    std::this_thread::sleep_for(std::chrono::seconds(3));

    sv->wait_stopped();
}
