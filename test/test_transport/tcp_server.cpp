#include "tcp_transport_test.h"

static service *sv;
static service *sv1;

static int send_pocket_size = 1024*4;

struct transport_context
{
	transport_context(tcp_transport_sptr t)
	{
		transport = t;
		all_read_size = 0;
		read_size = 0;
		read_pocket_size = 0;
		last_report_time = ::time(0);
		idx = t->get_fd();
	}

	tcp_transport_sptr transport;
	uint64 all_read_size;
	int32 read_size;
	int32 read_pocket_size;
	int32 last_report_time;
	int32 idx;

};

class my_tcp_acceptor :
	public std::enable_shared_from_this<my_tcp_acceptor>
{
public:
	my_tcp_acceptor()
	{
		send_data_.resize(send_pocket_size);
	}

	/*********************************************************************************
	 * Tcp accepted event callback
	 ********************************************************************************/
	void on_accepted_callback(base_transport_sptr transp)
	{
		tcp_transport_sptr transport = std::static_pointer_cast<tcp_transport>(transp);
		auto tctx = new transport_context(transport);
		transport->set_context(tctx);

		pump::transport_callbacks cbs;
		cbs.read_cb = function::bind(&my_tcp_acceptor::on_read_callback, this, transp.get(), _1, _2);
		cbs.stopped_cb = function::bind(&my_tcp_acceptor::on_stopped_callback, this, transp.get());
		cbs.disconnected_cb = function::bind(&my_tcp_acceptor::on_disconnected_callback, this, transp.get());

		if (transport->start(sv, 0, cbs) == 0)
		{
			std::lock_guard<std::mutex> lock(mx_);
			printf("tcp transport server accepted %d\n", transp->get_fd());
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
		transport_context* ctx = (transport_context*)transp->get_context();

		ctx->read_size += size;
		ctx->all_read_size += size;
		ctx->read_pocket_size += size;

		while (ctx->read_pocket_size >= send_pocket_size)
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
			printf("tcp transport disconnected all read size %fMB\n", (double)it->second->all_read_size/1024/1024);
			printf("tcp transport disconnected all read pocket %lld\n", it->second->all_read_size / 4096);
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
			printf("server tcp transport stopped\n");
			delete it->second;
		}
	}

	inline void send_data(base_transport_ptr transport)
	{
		transport->send(send_data_.data(), send_data_.size());
	}

private:
	std::string send_data_;

	std::mutex mx_;
	std::map<void_ptr, transport_context*> transports_;
};

void start_tcp_server(const std::string &ip, uint16 port)
{
	sv = new service;
	sv->start();

	sv1 = new service;
	sv1->start();

	my_tcp_acceptor *my_acceptor = new my_tcp_acceptor;

	pump::acceptor_callbacks cbs;
	cbs.accepted_cb = function::bind(&my_tcp_acceptor::on_accepted_callback, my_acceptor, _1);
	cbs.stopped_cb = function::bind(&my_tcp_acceptor::on_stopped_accepting_callback, my_acceptor);

	address listen_address(ip, port);
	tcp_acceptor_sptr acceptor = tcp_acceptor::create_instance(listen_address);
	if (acceptor->start(sv, cbs) != 0)
	{
		printf("tcp acceptor start error\n");
	}

	sv->wait_stopped();
}
