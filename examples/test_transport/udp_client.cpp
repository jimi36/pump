#include "udp_transport_test.h"

static librabbit::service *sv;

class my_udp_client: 
	public transport_udp_notifier
{
public:
	/*********************************************************************************
	 * Read event callback for udp
	 ********************************************************************************/
	virtual void on_recv_callback(transport_base_ptr transp, c_block_ptr b, int32 size, const address &remote_address)
	{

	}

	/*********************************************************************************
	 * Stopped event callback
	 ********************************************************************************/
	virtual void on_stopped_callback(transport_base_ptr transp)
	{

	}
};

void send(udp_transport_sptr transport, const std::string &ip, uint16 port)
{
	char buf[4096];
	librabbit::transport::address addr(ip, port);
	while (1)
	{
		if (transport->send(buf, 4096, addr) <= 0)
		{
			Sleep(100);
		}
	}
}

static std::shared_ptr<transport_udp_notifier> my_udp_notifier;

void start_udp_client(const std::string &ip, uint16 port)
{
	sv = new librabbit::service;
	sv->start();

	address localaddr("0.0.0.0", 0);
	my_udp_notifier.reset(new my_udp_client);
	udp_transport_sptr transport = librabbit::transport::udp_transport::create_instance();
	if (!transport->start(sv, localaddr, my_udp_notifier))
	{
		printf("udp client start error\n");
		return;
	}

	send(transport, ip, port);

	sv->wait_stop();
}
