#include <stdio.h>
#include <librabbit/service.h>
#include <librabbit/time/timer.h>

class Timeout: 
	public librabbit::time::timeout_notifier,
	public std::enable_shared_from_this<Timeout>
{
public:
	Timeout(librabbit::service *sv)
	{
		sv_ = sv;
	}

	void start()
	{
		auto notify = std::static_pointer_cast<timeout_notifier>(shared_from_this());
		t_.reset(new librabbit::time::timer(nullptr, notify, 1000, true));
		if (!sv_->start_timer(t_))
		{
			printf("start timeout error\n");
		}
	}

	/*********************************************************************************
	 * Timer timeout callback
	 ********************************************************************************/
	virtual void on_timer_timeout(void *arg)
	{
		printf("timeout event pending %d\n", time(0));
	}

private:
	librabbit::service *sv_;
	std::shared_ptr<librabbit::time::timer> t_;
};

int main(int argc, const char **argv)
{
	librabbit::service *sv = new librabbit::service;
	sv->start();

	std::shared_ptr<Timeout> t1(new Timeout(sv));
	t1->start();
	std::shared_ptr<Timeout> t2(new Timeout(sv));
	t2->start();

	sv->wait_stop();

	return 0;
}