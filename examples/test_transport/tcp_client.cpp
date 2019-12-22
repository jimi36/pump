#include "tcp_transport_test.h"

static service *sv;

static int send_loop = 512;
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
		rw_cnt = 0;
		read_size_ = 0;
		read_pocket_size_ = 0;
		all_read_size_ = 0;
		last_report_time_ = 0;
		send_data_.resize(send_pocket_size);
	}

	/*********************************************************************************
	 * Tcp dialed event callback
	 ********************************************************************************/
	virtual void on_dialed_callback(void_ptr ctx, transport_base_sptr transp)
	{
		transport_ = static_pointer_cast<tcp_transport>(transp);

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
	virtual void on_recv_callback(transport_base_ptr transp, c_block_ptr b, int32 size)
	{
		read_size_ += size;
		read_pocket_size_ += size;
		all_read_size_ += size;

		//assert(size == send_pocket_size);

		int64 now = ::time(0);
		if (last_report_time_ < now)
		{
			printf("client read wait %d speed is %fMB/s\n", rw_cnt.load(), (float)read_size_ / 1024 / 1024);

			read_size_ = 0;
			last_report_time_ = now;
		}

		while (read_pocket_size_ >= send_pocket_size)
		{
			rw_cnt.fetch_sub(1);
			send_data();
			read_pocket_size_ -= send_pocket_size;
		}
	}

	/*********************************************************************************
	 * Tcp data writed completed event callback
	 ********************************************************************************/
	virtual void on_sent_callback(transport_base_ptr transp)
	{
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
		printf("client tcp transport stopped\n");
		transport_.reset();
	}

	void set_dialer(tcp_dialer_sptr d)
	{
		dialer_ = d;
	}

	void send_data()
	{
		rw_cnt.fetch_add(1);
		transport_->send(send_data_.data(), send_data_.size());
	}

private:
	int32 read_size_;
	int32 read_pocket_size_;
	int32 all_read_size_;
	int64 last_report_time_;

	std::string send_data_;

	tcp_dialer_sptr dialer_;
	tcp_transport_sptr transport_;

	std::atomic_int rw_cnt;
};

static std::shared_ptr<my_tcp_dialer> my_dialed_notifier;

void start_tcp_client(const std::string &ip, uint16 port)
{
	sv = new service;
	sv->start();

	tcp_dialer_sptr dialer = tcp_dialer::create_instance();

	my_dialed_notifier.reset(new my_tcp_dialer);
	my_dialed_notifier->set_dialer(dialer);

	address bind_address("0.0.0.0", 0);
	address connect_address(ip, port);
	librabbit::dialed_notifier_sptr notifier = my_dialed_notifier;
	if (!dialer->start(sv, 0, bind_address, connect_address, notifier))
	{
		printf("tcp dialer start error\n");
	}

	while (getchar())
	{
		my_dialed_notifier->send_data();
		printf("c send\n");
	}

	sv->wait_stop();
}
