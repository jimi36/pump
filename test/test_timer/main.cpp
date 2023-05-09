#include <pump/init.h>
#include <pump/service.h>
#include <pump/time/timer.h>
#include <pump/time/timestamp.h>
#include <stdio.h>

pump::service *sv = nullptr;

class Timeout : public std::enable_shared_from_this<Timeout> {
  public:
    Timeout(pump::service *sv) {
        sv_ = sv;

        count_ = 0;
        last_report_time_ = 0;
    }

    void start() {
        printf("new timeout\n");
        auto cb = pump_bind(&Timeout::on_timer_timeout, this);
        for (int i = 1; i <= 1; i++) {
			uint64_t timeout = 5e9;
            auto t = pump::time::timer::create(true, timeout, cb);
            if (!sv_->start_timer(t)) {
                printf("start timeout error\n");
            }
            timers_.push_back(t);
        }
    }

    /*********************************************************************************
     * Timer timeout callback
     ********************************************************************************/
    void on_timer_timeout() {
        count_++;

        int32_t now = (int32_t)::time(0);
        if (last_report_time_ != now) {
            printf("timer pending count %d at %u\n", count_, time(0));
            last_report_time_ = now;
            count_ = 0;
        }
    }

  private:
    pump::service *sv_;

    typedef std::shared_ptr<pump::time::timer> timer_sptr;
    std::vector<timer_sptr> timers_;

    int32_t count_;
    int32_t last_report_time_;
};

void timeout() {
    printf("timeout callback\n");
}

void timeout_ex(pump::time::timer_sptr &t) {
    if (t) {
        printf("timer ok\n");
    }
    sv->start_timer(t);
}

int main(int argc, const char **argv) {
    pump::init();

    sv = new pump::service();
    sv->start();

    //std::shared_ptr<Timeout> t1(new Timeout(sv));
    //t1->start();

    //pump::time::sync_timer st(5000000000, pump_bind(timeout));
    //sv->start_sync_timer(st);

    auto t = pump::time::timer::create(false, 2000000000);
    pump::time::timer_wptr wt = t;
    t->set_callback(pump_bind(timeout_ex, t));
    sv->start_timer(t);
    //t.reset();

    Sleep(5000);

    //printf("begin %llums\n", pump::time::get_clock_milliseconds());
    auto b_us = pump::time::get_clock_microseconds();
    //printf("begin %lluns\n", pump::time::get_clock_nanoseconds());

    //if (wt.lock()) {
        //printf("weak timer ok\n");
    //} else {
        //printf("weak timer not ok\n");
    //}

    //printf("end %llums\n", pump::time::get_clock_milliseconds());
    printf("end %llu %lluus\n", b_us, pump::time::get_clock_microseconds());
    //printf("end %lluns\n", pump::time::get_clock_nanoseconds());

    sv->wait_stopped();

    return 0;
}
