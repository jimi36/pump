#include "http.h"

void on_new_request(http::connection_wptr &wconn, http::request_sptr &&req)
{
	static std::string data = "hello world 1!!!";

	http::response res;
	res.set_status_code(200);
	res.set_http_version(http::VERSION_11);
	res.get_header()->set("Content-Type", "text/html; charset=utf-8");
	res.get_header()->set("Content-Length", data.size());
	//res.get_header()->set("Transfer-Encoding", "chunked");
	//conn->send(&res);

	http::content_sptr content(new http::content);
	content->append(data.c_str(), data.size());
	res.set_content(content);

	auto conn = wconn.lock();
	conn->send(&res);
}

void on_stopped()
{
	printf("http server stopped\n");
}

void start_http_server(pump::service_ptr sv, const std::string &ip, int port)
{
	pump::transport::address bind_address(ip, port);

	http::server_callbacks cbs;
	cbs.request_cb = pump_bind(&on_new_request, _1, _2);
	cbs.stopped_cb = pump_bind(&on_stopped);

	auto svr = http::server::create_instance();
	//if (!svr->start(sv, "cert.pem", "key.pem", bind_address, cbs))
	if (!svr->start(sv, bind_address, cbs))
		printf("http server start error\n");
	else
		printf("http server started\n");
	
	sv->wait_stopped();
}