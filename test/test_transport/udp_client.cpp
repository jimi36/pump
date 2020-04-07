#include "udp_transport_test.h"

static service *sv;

class my_udp_client: 
	public transport_io_notifier,
	public transport_terminated_notifier
{
public:
	/*********************************************************************************
	 * Read event callback for udp
	 ********************************************************************************/
	virtual void on_read_callback(transport_base_ptr transp, c_block_ptr b, int32 size, const address &remote_address)
	{

	}

	/*********************************************************************************
	 * Stopped event callback
	 ********************************************************************************/
	virtual void on_stopped_callback(transport_base_ptr transp)
	{
	}

	/*********************************************************************************
	 * Disconnected event callback
	 ********************************************************************************/
	virtual void on_disconnected_callback(transport_base_ptr transp)
	{
	}
};

void send(udp_transport_sptr transport, const std::string &ip, uint16 port)
{
	char buf[4096];
	address addr(ip, port);
	while (1)
	{
		if (transport->send(buf, 4096, addr) <= 0)
		{
#ifdef WIN32
			Sleep(100);
#else
			usleep(1000);
#endif
		}
	}
}

static std::shared_ptr<my_udp_client> udp_client;

void start_udp_client(const std::string &ip, uint16 port)
{
	sv = new service;
	sv->start();

	address localaddr("0.0.0.0", 0);
	udp_client.reset(new my_udp_client);
	transport_io_notifier_sptr io_notifier = udp_client;
	transport_terminated_notifier_sptr terminated_notifier = udp_client;
	udp_transport_sptr transport = udp_transport::create_instance();
	if (!transport->start(sv, localaddr, io_notifier, terminated_notifier))
	{
		printf("udp client start error\n");
		return;
	}

	send(transport, ip, port);

	sv->wait_stopped();
}
