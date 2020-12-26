#include <pump/service.h>
#include <pump/time/timer.h>
#include <stdio.h>

class Timeout : public std::enable_shared_from_this<Timeout> {
  public:
    Timeout(pump::service *sv) {
        sv_ = sv;

        count_ = 0;
        last_report_time_ = 0;
    }

    void start() {
        printf("new timeout\n");
        pump::time::timer_callback cb = pump_bind(&Timeout::on_timer_timeout, this);
        for (int i = 0; i < 1; i++) {
            auto t = pump::time::timer::create(10, cb, true);
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
            printf("timer pending count %d\n", count_);
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

int main(int argc, const char **argv) {
    
    pump::service *sv = new pump::service;
    sv->start();

    std::shared_ptr<Timeout> t1(new Timeout(sv));
    t1->start();

    sv->wait_stopped();

    return 0;
}
