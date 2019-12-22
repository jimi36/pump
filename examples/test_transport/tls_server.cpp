#include "tls_transport_test.h"

#ifdef USE_GNUTLS
#include <gnutls/gnutls.h>
#endif

static service *sv;

static int send_loop = 0;
static int send_pocket_size = 1024 * 4;

struct transport_context
{
	transport_context(tls_transport_sptr t)
	{
		transport = t;
		read_size = 0;
		read_pocket_size = 0;
		last_report_time = ::time(0);
		idx = t->get_fd();
	}

	tls_transport_sptr transport;
	int32 read_size;
	int32 read_pocket_size;
	int32 last_report_time;
	int32 idx;

};

class my_tls_acceptor: 
	public accepted_notifier,
	public transport_io_notifier,
	public transport_terminated_notifier,
	public std::enable_shared_from_this<my_tls_acceptor>
{
public:
	my_tls_acceptor()
	{
		send_data_.resize(send_pocket_size);
	}

	/*********************************************************************************
	 * Tcp accepted event callback
	 ********************************************************************************/
	virtual void on_accepted_callback(void_ptr ctx, transport_base_sptr transp)
	{
		tls_transport_sptr transport = static_pointer_cast<tls_transport>(transp);

		transport_io_notifier_sptr io_notifier = shared_from_this();
		transport_terminated_notifier_sptr terminated_notifier = shared_from_this();
		if (transport->start(sv, io_notifier, terminated_notifier))
		{
			std::lock_guard<std::mutex> lock(mx_);
			printf("server tls transport accepted\n");
			transports_[transp.get()] = new transport_context(transport);
		}

		for (int i = 0; i < send_loop; i++)
		{
			send_data(transport.get());
		}
	}

	/*********************************************************************************
	 * Stopped accepting event callback
	 ********************************************************************************/
	virtual void on_stopped_accepting_callback(void_ptr ctx)
	{

	}

	/*********************************************************************************
	 * Tcp read event callback
	 ********************************************************************************/
	virtual void on_recv_callback(transport_base_ptr transp, c_block_ptr b, int32 size)
	{
		std::lock_guard<std::mutex> lock(mx_);
		auto it = transports_.find(transp);
		if (it != transports_.end())
		{
			it->second->read_pocket_size += size;
			it->second->read_size += size;

			if (it->second->last_report_time < ::time(0))
			{
				printf("transport %d read speed is %fMB/s\n", it->second->idx, (float)it->second->read_size / 1024 / 1024);
				it->second->read_size = it->second->read_size % send_pocket_size;

				it->second->last_report_time = ::time(0);
			}

			while (it->second->read_pocket_size >= send_pocket_size)
			{
				it->second->read_pocket_size -= send_pocket_size;
				send_data(it->second->transport.get());
			}
		}
	}

	/*********************************************************************************
	 * Tls data writed completed event callback
	 ********************************************************************************/
	virtual void on_sent_callback(transport_base_ptr transp)
	{
	}

	/*********************************************************************************
	 * Tcp disconnected event callback
	 ********************************************************************************/
	virtual void on_disconnected_callback(transport_base_ptr transp)
	{
		std::lock_guard<std::mutex> lock(mx_);
		auto it = transports_.find(transp);
		if (it != transports_.end())
		{
			printf("server tls transport disconnected\n");
			delete it->second;
			transports_.erase(it);
		}
	}

	/*********************************************************************************
	 * Tcp stopped event callback
	 ********************************************************************************/
	virtual void on_stopped_callback(transport_base_ptr transp)
	{
		std::lock_guard<std::mutex> lock(mx_);
		auto it = transports_.find(transp);
		if (it != transports_.end())
		{
			printf("server tls transport stopped\n");
			delete it->second;
		}
	}

	void send_data(tls_transport_ptr transport)
	{
		if (!transport->send(send_data_.data(), send_data_.size()))
			printf("send data error\n");
	}

private:
	std::string send_data_;

	std::mutex mx_;
	std::map<void_ptr, transport_context*> transports_;
};

static std::shared_ptr<accepted_notifier> my_accpeted_notifier;

void start_tls_server(const std::string &ip, uint16 port, const std::string &cert_file, const std::string &key_file)
{
#ifdef USE_GNUTLS
	if (gnutls_global_init() != 0)
		return;

	gnutls_global_set_log_level(0);

	int ret = 0;
	gnutls_certificate_credentials_t xcred;
	ret = gnutls_certificate_allocate_credentials(&xcred);
	if (ret != 0)
		return;
	ret = gnutls_certificate_set_x509_key_file(xcred, cert_file.c_str(), key_file.c_str(), GNUTLS_X509_FMT_PEM);
	if (ret != 0)
		return;
	//gnutls_certificate_set_ocsp_status_request_file(xcred, OCSP_STATUS_FILE, 0);

	sv = new service;
	sv->start();

	my_accpeted_notifier.reset(new my_tls_acceptor);

	address listen_address(ip, port);
	tls_acceptor_sptr acceptor = tls_acceptor::create_instance();
	if (!acceptor->start(xcred, sv, 0, listen_address, my_accpeted_notifier))
	{
		printf("tls acceptor start error\n");
	}

	sv->wait_stop();
#endif
}

