#include "tls_transport_test.h"

#ifdef USE_GNUTLS
#include <gnutls/gnutls.h>
#endif

static service *sv;

static int send_loop = 1024;
static int send_pocket_size = 1024*4;

class my_tls_dialer :
	public dialed_notifier,
	public transport_io_notifier,
	public transport_terminated_notifier,
	public std::enable_shared_from_this<my_tls_dialer>
{
public:
	my_tls_dialer()
	{
		read_size_ = 0;
		read_pocket_size_ = 0;
		send_data_.resize(send_pocket_size);
	}

	/*********************************************************************************
	 * Tls dialed event callback
	 ********************************************************************************/
	virtual void on_dialed_callback(void_ptr ctx, transport_base_sptr transp, bool succ)
	{
		if (!succ)
		{
			printf("tls cleint dialed error\n");
			return;
		}

		transport_ = std::static_pointer_cast<tls_transport>(transp);

		transport_io_notifier_sptr io_notifier = shared_from_this();
		transport_terminated_notifier_sptr terminated_notifier = shared_from_this();
		if (!transport_->start(sv, io_notifier, terminated_notifier))
			return;

		printf("tls client dialed\n");

		for (int i = 0; i < send_loop; i++)
		{
			send_data();
		}
	}

	/*********************************************************************************
	 * Tls dialed error event callback
	 ********************************************************************************/
	virtual void on_dialed_error_callback(void_ptr ctx)
	{
		printf("tls client transport dialed error\n");
	}

	/*********************************************************************************
	 * Tls dialed timeout event callback
	 ********************************************************************************/
	virtual void on_dialed_timeout_callback(void_ptr ctx)
	{
		printf("tls client transport dialed timeout\n");
	}

	/*********************************************************************************
	 * Stopped dial event callback
	 ********************************************************************************/
	virtual void on_stopped_dialing_callback(void_ptr ctx)
	{
		printf("tls client dial stopped\n");
	}

	/*********************************************************************************
	 * Tls read event callback
	 ********************************************************************************/
	virtual void on_read_callback(transport_base_ptr transp, c_block_ptr b, int32 size)
	{
		read_size_ += size;
		read_pocket_size_ += size;

		while (read_pocket_size_ >= send_pocket_size)
		{
			read_pocket_size_ -= send_pocket_size;
			send_data();
		}
	}

	/*********************************************************************************
	 * Tls disconnected event callback
	 ********************************************************************************/
	virtual void on_disconnected_callback(transport_base_ptr transp)
	{
		printf("client tls transport disconnected\n");
		transport_.reset();
	}

	/*********************************************************************************
	 * Tls stopped event callback
	 ********************************************************************************/
	virtual void on_stopped_callback(transport_base_ptr transp)
	{
		printf("client tls transport stopped\n");
	}

	void send_data()
	{
		if (!transport_->send(send_data_.data(), send_data_.size()))
			printf("send data error\n");
	}

	void set_dialer(tls_dialer_sptr dialer)
	{
		dialer_ = dialer;
	}

public:
	int32 read_size_;
	int32 read_pocket_size_;
	int64 last_report_time_;

	std::string send_data_;

	tls_transport_sptr transport_;

	tls_dialer_sptr dialer_;
};

static int count = 10;

static std::vector< std::shared_ptr<my_tls_dialer>> my_dialers;

class tls_time_report :
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

void start_tls_client(const std::string &ip, uint16 port)
{
#ifdef USE_GNUTLS
	if (gnutls_global_init() != 0)
		return;

	gnutls_global_set_log_level(0);

	gnutls_certificate_credentials_t xcred;
	gnutls_certificate_allocate_credentials(&xcred);
	gnutls_certificate_set_x509_system_trust(xcred);

	sv = new service;
	sv->start();

	for (int i = 0; i < count; i++)
	{
		tls_dialer_sptr dialer = tls_dialer::create_instance();

		std::shared_ptr<my_tls_dialer> my_dialer(new my_tls_dialer);
		my_dialer->set_dialer(dialer);

		my_dialers.push_back(my_dialer);

		address bind_address("0.0.0.0", 0);
		address remote_address(ip, port);
		pump::dialed_notifier_sptr notifier = my_dialer;
		if (!dialer->start(xcred, sv, 0, 0, bind_address, remote_address, notifier))
		{
			printf("tls dialer start error\n");
		}
	}

	timeout_notifier_sptr notifier(new tls_time_report);
	timer_sptr t(new timer(0, notifier, 1000, true));

	sv->start_timer(t);

	sv->wait_stopped();
#endif
}
