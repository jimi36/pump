#include <stdio.h>
#include <pump/service.h>
#include <pump/time/timer.h>

void operator delete(void *ptr) noexcept {
	free(ptr);
}

void operator delete[](void *ptr) noexcept {
	free(ptr);
}

void operator delete(void *ptr, const std::nothrow_t &) noexcept {
	free(ptr);
}

class Timeout: 
	public pump::time::timeout_notifier,
	public std::enable_shared_from_this<Timeout>
{
public:
	Timeout(pump::service *sv)
	{
		sv_ = sv;
	}

	void start()
	{
		auto notify = std::static_pointer_cast<timeout_notifier>(shared_from_this());
		printf("new timeout\n");
		t_.reset(new pump::time::timer(nullptr, notify, 1000, true));
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
		//sv_->stop();
		t_.reset();
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