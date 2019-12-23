#include "udp_transport_test.h"

static service *sv;

class my_udp_server_notify: 
	public transport_udp_notifier
{
public:
	my_udp_server_notify()
	{
		read_size_ = 0;
		last_report_time_ = ::time(0);
	}

	/*********************************************************************************
	 * Udp read event callback
	 ********************************************************************************/
	virtual void on_recv_callback(transport_base_ptr transp, c_block_ptr b, int32 size, const address &remote_address)
	{
		if (size > 0)
			read_size_ += size;

		uint64 now = ::time(0);
		if (now > last_report_time_)
		{
			float32 speed = (float32)read_size_ / 1024 / 1024 / (now - last_report_time_);
			printf("read speed %02f M/s\n", speed);

			read_size_ = 0;
			last_report_time_ = now;
		}
	}

	/*********************************************************************************
	 * Stopped event callback
	 ********************************************************************************/
	virtual void on_stopped_callback(transport_base_ptr transp)
	{

	}

private:
	int32 read_size_;
	uint64 last_report_time_;
};

static std::shared_ptr<transport_udp_notifier> my_udp_notifier;

void start_udp_server(const std::string &ip, uint16 port)
{
	sv = new service;
	sv->start();

	address localaddr(ip, port);
	my_udp_notifier.reset(new my_udp_server_notify);
	udp_transport_sptr transport = udp_transport::create_instance();
	if (!transport->start(sv, localaddr, my_udp_notifier))
	{
		printf("udp server start error\n");
	}

	sv->wait_stop();
}
