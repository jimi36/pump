#include <stdio.h>
#include <pump/service.h>
#include <pump/time/timer.h>

class Timeout: 
	public std::enable_shared_from_this<Timeout>
{
public:
	Timeout(pump::service *sv)
	{
		sv_ = sv;
	}

	void start()
	{
		printf("new timeout\n");
		pump::time::timer_callback cb = function::bind(&Timeout::on_timer_timeout, this);
		t_.reset(new pump::time::timer(cb, 1000, true));
		if (!sv_->start_timer(t_))
		{
			printf("start timeout error\n");
		}
	}

	/*********************************************************************************
	 * Timer timeout callback
	 ********************************************************************************/
	void on_timer_timeout()
	{
		printf("timeout event pending %d\n", time(0));
		//sv_->stop();
		//t_.reset();
	}

private:
	pump::service *sv_;
	std::shared_ptr<pump::time::timer> t_;
};

int main(int argc, const char **argv)
{
	auto tm = new pump::time::timestamp;

	pump::service *sv = new pump::service;
	sv->start();

	std::shared_ptr<Timeout> t1(new Timeout(sv));
	t1->start();

	sv->wait_stopped();

	return 0;
}