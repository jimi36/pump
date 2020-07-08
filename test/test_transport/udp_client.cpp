#include "udp_transport_test.h"

static service *sv;

class my_udp_client
{
public:
	/*********************************************************************************
	 * Read event callback for udp
	 ********************************************************************************/
	virtual void on_read_callback(base_transport_ptr transp, c_block_ptr b, int32 size, const address &remote_address)
	{

	}

	/*********************************************************************************
	 * Stopped event callback
	 ********************************************************************************/
	virtual void on_stopped_callback(base_transport_ptr transp)
	{
	}

	/*********************************************************************************
	 * Disconnected event callback
	 ********************************************************************************/
	virtual void on_disconnected_callback(base_transport_ptr transp)
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

	udp_client.reset(new my_udp_client);

	address localaddr("0.0.0.0", 0);
	udp_transport_sptr transport = udp_transport::create_instance(localaddr);

	pump::transport_callbacks cbs;
	cbs.read_from_cb = pump_bind(&my_udp_client::on_read_callback, udp_client.get(), transport.get(), _1, _2, _3);
	cbs.stopped_cb = pump_bind(&my_udp_client::on_stopped_callback, udp_client.get(), transport.get());

	if (!transport->start(sv, 0, cbs))
	{
		printf("udp client start error\n");
		return;
	}

	send(transport, ip, port);

	sv->wait_stopped();
}
