#include <pump/service.h>
#include <pump/time/timer.h>
#include <stdio.h>

class Timeout : public std::enable_shared_from_this<Timeout> {
  public:
    Timeout(pump::service *sv) { sv_ = sv; }

    void start() {
        printf("new timeout\n");
        pump::time::timer_callback cb =
            pump_bind(&Timeout::on_timer_timeout, this);
        t_ = pump::time::timer::create(1000, cb, true);
        if (!sv_->start_timer(t_)) {
            printf("start timeout error\n");
        }
    }

    /*********************************************************************************
     * Timer timeout callback
     ********************************************************************************/
    void on_timer_timeout() {
        printf("timeout event pending %llu\n",
               pump::time::get_clock_milliseconds());
    }

  private:
    pump::service *sv_;
    std::shared_ptr<pump::time::timer> t_;
};

int main(int argc, const char **argv) {
    auto tm = new pump::time::timestamp;

    pump::service *sv = new pump::service;
    sv->start();

    std::shared_ptr<Timeout> t1(new Timeout(sv));
    t1->start();

    sv->wait_stopped();

    return 0;
}
