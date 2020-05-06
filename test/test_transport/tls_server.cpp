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
	uint64 read_size;
	int32 read_pocket_size;
	int32 last_report_time;
	int32 idx;

};

class my_tls_acceptor: 
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
	void on_accepted_callback(base_transport_sptr transp)
	{
		tls_transport_sptr transport = std::static_pointer_cast<tls_transport>(transp);
		auto tctx = new transport_context(transport);
		transport->set_context(tctx);

		pump::transport_callbacks cbs;
		cbs.read_cb = function::bind(&my_tls_acceptor::on_read_callback, this, transp.get(), _1, _2);
		cbs.stopped_cb = function::bind(&my_tls_acceptor::on_stopped_callback, this, transp.get());
		cbs.disconnected_cb = function::bind(&my_tls_acceptor::on_disconnected_callback, this, transp.get());

		if (transport->start(sv, cbs))
		{
			std::lock_guard<std::mutex> lock(mx_);
			printf("server tls transport accepted %d\n", transp->get_fd());
			transports_[transp.get()] = tctx;
		}
	}

	/*********************************************************************************
	 * Stopped accepting event callback
	 ********************************************************************************/
	void on_stopped_accepting_callback()
	{
	}

	/*********************************************************************************
	 * Tcp read event callback
	 ********************************************************************************/
	void on_read_callback(base_transport_ptr transp, c_block_ptr b, int32 size)
	{
		static int last_fd = 0;
		if (last_fd != transp->get_fd())
		{
			//printf("transport %d read\n", transp->get_fd());
			last_fd = transp->get_fd();
		}

		transport_context* ctx = (transport_context*)transp->get_context();

		ctx->read_pocket_size += size;
		ctx->read_size += size;

		if (ctx->read_pocket_size >= send_pocket_size)
		{
			ctx->read_pocket_size -= send_pocket_size;
			send_data(transp);
		}
	}

	/*********************************************************************************
	 * Tcp disconnected event callback
	 ********************************************************************************/
	void on_disconnected_callback(base_transport_ptr transp)
	{
		std::lock_guard<std::mutex> lock(mx_);
		auto it = transports_.find(transp);
		if (it != transports_.end())
		{
			printf("tls transport %d disconnected all read size %fMB\n", transp->get_fd(), (double)it->second->read_size / 1024 / 1024);
			printf("tls transport %d disconnected all read pocket %lld\n", transp->get_fd(), it->second->read_size / 4096);
			delete it->second;
			transports_.erase(it);
		}
	}

	/*********************************************************************************
	 * Tcp stopped event callback
	 ********************************************************************************/
	void on_stopped_callback(base_transport_ptr transp)
	{
		std::lock_guard<std::mutex> lock(mx_);
		auto it = transports_.find(transp);
		if (it != transports_.end())
		{
			printf("tls transport disconnected all read size %fMB\n", (double)it->second->read_size / 1024 / 1024);
			printf("tls transport disconnected all read pocket %llu\n", it->second->read_size / 4096);
			delete it->second;
		}
	}

	void send_data(base_transport_ptr transport)
	{
		if (!transport->send(send_data_.data(), send_data_.size()))
			printf("send data error\n");
	}

private:
	std::string send_data_;

	std::mutex mx_;
	std::map<void_ptr, transport_context*> transports_;
};

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
	{
		auto str = gnutls_strerror(ret);
		printf("%s\n", str);
		return;
	}
	//gnutls_certificate_set_ocsp_status_request_file(xcred, OCSP_STATUS_FILE, 0);

	sv = new service;
	sv->start();

	my_tls_acceptor *my_acceptor = new my_tls_acceptor;

	pump::acceptor_callbacks cbs;
	cbs.accepted_cb = function::bind(&my_tls_acceptor::on_accepted_callback, my_acceptor, _1);
	cbs.stopped_cb = function::bind(&my_tls_acceptor::on_stopped_accepting_callback, my_acceptor);

	address listen_address(ip, port);
	tls_acceptor_sptr acceptor = tls_acceptor::create_instance(xcred, listen_address);
	if (!acceptor->start(sv, cbs))
	{
		printf("tls acceptor start error\n");
	}

	sv->wait_stopped();
#endif
}

