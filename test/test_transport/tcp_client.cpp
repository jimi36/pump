#include "tcp_transport_test.h"

static service *sv;

static int count = 1;
static int max_send_cont = 1024 * 256 * 10;
static int send_loop = 1;
static int send_pocket_size = 1024*4;

class my_tcp_dialer :
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
	void on_dialed_callback(base_transport_sptr transp, bool succ)
	{
		if (!succ)
		{
			printf("tcp client dialed error\n");
			return;
		}

		pump::transport_callbacks cbs;
		cbs.read_cb = function::bind(&my_tcp_dialer::on_read_callback, this, transp.get(), _1, _2);
		cbs.stopped_cb = function::bind(&my_tcp_dialer::on_stopped_callback, this, transp.get());
		cbs.disconnected_cb = function::bind(&my_tcp_dialer::on_disconnected_callback, this, transp.get());

		transport_ = std::static_pointer_cast<tcp_transport>(transp);
		if (transport_->start(sv, 4096*1024, cbs) != 0)
			return;
		
		printf("tcp client dialed\n");

		for (int i = 0; i < send_loop; i++)
		{
			send_data();
		}
	}

	/*********************************************************************************
	 * Tcp dialed timeout event callback
	 ********************************************************************************/
	void on_dialed_timeout_callback()
	{
		printf("tcp client dial timeout\n");
	}

	/*********************************************************************************
	 * Stopped dial event callback
	 ********************************************************************************/
	void on_stopped_dialing_callback()
	{
		printf("tcp client dial stopped\n");
	}

	/*********************************************************************************
	 * Tcp read event callback
	 ********************************************************************************/
	void on_read_callback(base_transport_ptr transp, c_block_ptr b, int32 size)
	{
		read_size_ += size;
		all_read_size_ += size;
		read_pocket_size_ += size;

		if (read_pocket_size_ >= send_pocket_size)
		{
			read_pocket_size_ -= send_pocket_size;
			send_data();
		}
	}

	/*********************************************************************************
	 * Tcp disconnected event callback
	 ********************************************************************************/
	void on_disconnected_callback(base_transport_ptr transp)
	{
		printf("client tcp transport disconnected read msg %d\n", all_read_size_ / 4096);
		transport_.reset();
	}

	/*********************************************************************************
	 * Tcp stopped event callback
	 ********************************************************************************/
	void on_stopped_callback(base_transport_ptr transp)
	{
		printf("client tcp transport stopped read msg %d\n", all_read_size_ / 4096);
		transport_.reset();
	}

	void set_dialer(tcp_dialer_sptr d)
	{
		dialer_ = d;
	}

	inline bool send_data()
	{
		if (transport_->send(send_data_.data(), send_data_.size()) != 0)
		{
			return false;
		}
		
		return true;
	}

public:
	volatile int32 read_size_;
	volatile int32 read_pocket_size_;
	int32 all_read_size_;
	int64 last_report_time_;

	int64 max_send_count_;

	std::string send_data_;

	tcp_dialer_sptr dialer_;
	tcp_transport_sptr transport_;
};

static std::vector< std::shared_ptr<my_tcp_dialer>> my_dialers;

class time_report
{
public:
	static void on_timer_timeout()
	{
		int read_size = 0;
		for (int i = 0; i < count; i++)
		{
			int size = my_dialers[i]->read_size_;
			if (size > 1024 * 1024 * 10)
			{
				auto pen_ps = my_dialers[i]->transport_->get_pending_send_size();
				auto new_ps = my_dialers[i]->transport_->get_max_pending_send_size();
				if (new_ps <= 4096 * 8)
					new_ps -= 4096;
				else
					new_ps /= 2;
				printf("ps %u %u\n", pen_ps, new_ps);
				my_dialers[i]->transport_->set_max_pending_send_size(new_ps);
			}

			read_size += size;
			my_dialers[i]->read_size_ = 0;
		}
		printf("client read speed is %fMB/s at %llu\n", (double)read_size / 1024 / 1024 / 1, ::time(0));
	}
};

void start_tcp_client(const std::string &ip, uint16 port)
{
	sv = new service;
	sv->start();

	for (int i = 0; i < count; i++)
	{
		address bind_address("0.0.0.0", 0);
		address peer_address(ip, port);
		tcp_dialer_sptr dialer = tcp_dialer::create_instance(bind_address, peer_address);

		std::shared_ptr<my_tcp_dialer> my_dialer(new my_tcp_dialer);
		my_dialer->set_dialer(dialer);
		my_dialers.push_back(my_dialer);

		pump::dialer_callbacks cbs;
		cbs.dialed_cb = function::bind(&my_tcp_dialer::on_dialed_callback, my_dialer.get(), _1, _2);
		cbs.stopped_cb = function::bind(&my_tcp_dialer::on_stopped_dialing_callback, my_dialer.get());
		cbs.timeout_cb = function::bind(&my_tcp_dialer::on_dialed_timeout_callback, my_dialer.get());

		if (dialer->start(sv, cbs) != 0)
		{
			printf("tcp dialer start error\n");
		}
	}

	pump::timer_callback cb = function::bind(&time_report::on_timer_timeout);
	timer_sptr t = pump::timer::create_instance(1000*1, cb, true);
	sv->start_timer(t);

	sv->wait_stopped();
}
