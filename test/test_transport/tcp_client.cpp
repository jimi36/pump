#include "tcp_transport_test.h"

static service *sv;

static int max_send_cont = 1024 * 256;
static int send_loop = 1024;
static int send_pocket_size = 1024*4;

class my_tcp_dialer :
	public dialed_notifier,
	public transport_io_notifier,
	public transport_terminated_notifier,
	public std::enable_shared_from_this<my_tcp_dialer>
{
public:
	my_tcp_dialer()
	{
		read_size_ = 0;
		read_pocket_size_ = 0;
		all_read_size_ = 0;
		last_report_time_ = 0;
		max_send_count_ = max_send_cont;
		send_data_.resize(send_pocket_size);
	}

	/*********************************************************************************
	 * Tcp dialed event callback
	 ********************************************************************************/
	virtual void on_dialed_callback(void_ptr ctx, transport_base_sptr transp, bool succ)
	{
		if (!succ)
		{
			printf("tcp client dialed error\n");
			return;
		}		

		transport_ = std::static_pointer_cast<tcp_transport>(transp);

		transport_io_notifier_sptr io_notifier = shared_from_this();
		transport_terminated_notifier_sptr terminated_notifier = shared_from_this();
		if (!transport_->start(sv, io_notifier, terminated_notifier))
			return;
		
		printf("tcp client dialed\n");

		for (int i = 0; i < send_loop; i++)
		{
			send_data();
		}
	}

	/*********************************************************************************
	 * Tcp dialed error event callback
	 ********************************************************************************/
	virtual void on_dialed_error_callback(void_ptr ctx)
	{
		printf("tcp client dial error\n");
	}

	/*********************************************************************************
	 * Tcp dialed timeout event callback
	 ********************************************************************************/
	virtual void on_dialed_timeout_callback(void_ptr ctx)
	{
		printf("tcp client dial timeout\n");
	}

	/*********************************************************************************
	 * Stopped dial event callback
	 ********************************************************************************/
	virtual void on_stopped_dialing_callback(void_ptr ctx)
	{
		printf("tcp client dial stopped\n");
	}

	/*********************************************************************************
	 * Tcp read event callback
	 ********************************************************************************/
	virtual void on_read_callback(transport_base_ptr transp, c_block_ptr b, int32 size)
	{
		read_size_ += size;
		read_pocket_size_ += size;
		all_read_size_ += size;

		//assert(size == 4096);

		while (read_pocket_size_ >= send_pocket_size)
		{
			read_pocket_size_ -= send_pocket_size;
			send_data();
		}

		//if (all_read_size_ / 4096 == max_send_cont);
		//	transp->stop();
	}

	/*********************************************************************************
	 * Tcp disconnected event callback
	 ********************************************************************************/
	virtual void on_disconnected_callback(transport_base_ptr transp)
	{
		printf("client tcp transport disconnected read msg %d\n", all_read_size_ / 4096);
		transport_.reset();
	}

	/*********************************************************************************
	 * Tcp stopped event callback
	 ********************************************************************************/
	virtual void on_stopped_callback(transport_base_ptr transp)
	{
		printf("client tcp transport stopped read msg %d\n", all_read_size_ / 4096);
		transport_.reset();
	}

	void set_dialer(tcp_dialer_sptr d)
	{
		dialer_ = d;
	}

	void send_data()
	{
		//if (max_send_count_ == 0)
		//	return;

		transport_->send(send_data_.data(), send_data_.size());

		max_send_count_--;
	}

public:
	volatile int32 read_size_;
	int32 read_pocket_size_;
	int32 all_read_size_;
	int64 last_report_time_;

	int64 max_send_count_;

	std::string send_data_;

	tcp_dialer_sptr dialer_;
	tcp_transport_sptr transport_;
};

static int count = 1;

static std::vector< std::shared_ptr<my_tcp_dialer>> my_dialers;

class time_report:
	public timeout_notifier
{
protected:
	virtual void on_timer_timeout(void_ptr arg)
	{
		int read_size = 0;
		for (int i = 0; i < count; i++)
		{
			read_size += my_dialers[i]->read_size_;
			my_dialers[i]->read_size_ = 0;
		}
		printf("client read speed is %fMB/s\n", (float)read_size / 1024 / 1024);
	}
};

void start_tcp_client(const std::string &ip, uint16 port)
{
	sv = new service;
	sv->start();

	for (int i = 0; i < count; i++)
	{
		tcp_dialer_sptr dialer = tcp_dialer::create_instance();

		std::shared_ptr<my_tcp_dialer> my_dialer(new my_tcp_dialer);
		my_dialer->set_dialer(dialer);

		my_dialers.push_back(my_dialer);

		address bind_address("0.0.0.0", 0);
		address connect_address(ip, port);
		pump::dialed_notifier_sptr notifier = my_dialer;
		if (!dialer->start(sv, 0, bind_address, connect_address, notifier))
		{
			printf("tcp dialer start error\n");
		}
	}

	timeout_notifier_sptr notifier(new time_report);
	timer_sptr t(new timer(0, notifier, 1000, true));

	sv->start_timer(t);

	sv->wait_stopped();
}
