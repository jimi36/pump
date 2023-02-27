/*
 * Copyright (C) 2015-2018 ZhengHaiTao <ming8ren@163.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef pump_proto_http_server_h
#define pump_proto_http_server_h

#include <pump/proto/http/request.h>
#include <pump/proto/http/response.h>
#include <pump/proto/http/connection.h>
#include <pump/transport/tcp_acceptor.h>
#include <pump/transport/tls_acceptor.h>

namespace pump {
namespace proto {
namespace http {

using transport::address;
using transport::base_acceptor_sptr;
using transport::tls_credentials;

class server;
DEFINE_SMART_POINTERS(server);

struct server_callbacks {
    // Http request callback
    pump_function<void(connection_wptr &, request_sptr &&)> request_cb;
    // Http server stopped callback
    pump_function<void()> stopped_cb;
};

class pump_lib server : public std::enable_shared_from_this<server> {
  public:
    /*********************************************************************************
     * Create instance
     ********************************************************************************/
    pump_inline static server_sptr create() {
        pump_object_create_inline(obj, server, ());
        return server_sptr(obj, pump_object_destroy<server>);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~server() = default;

    /*********************************************************************************
     * Start server
     ********************************************************************************/
    bool start(
        service *sv,
        const address &listen_address,
        const server_callbacks &cbs);

    /*********************************************************************************
     * Start server with tls
     ********************************************************************************/
    bool start(
        service *sv,
        tls_credentials xcred,
        const address &listen_address,
        const server_callbacks &cbs);

    /*********************************************************************************
     * Stop server
     ********************************************************************************/
    void stop();

  protected:
    /*********************************************************************************
     * Acceptor accepted callback
     ********************************************************************************/
    static void on_accepted(
        server_wptr svr,
        base_transport_sptr &transp);

    /*********************************************************************************
     * Acceptor stopped callback
     ********************************************************************************/
    static void on_stopped(server_wptr svr);

  protected:
    /*********************************************************************************
     * Http request callback
     ********************************************************************************/
    static void on_http_request(
        server_wptr svr,
        connection_wptr conn,
        packet_sptr &pk);

    /*********************************************************************************
     * Http error callback
     ********************************************************************************/
    static void on_http_error(
        server_wptr svr,
        connection_wptr conn,
        const std::string &msg);

  private:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    server() noexcept;

  private:
    // Service
    service *sv_;

    // Acceptor
    base_acceptor_sptr acceptor_;

    // Connections
    std::mutex conn_mx_;
    std::map<connection *, connection_sptr> conns_;

    // Server callbacks
    server_callbacks cbs_;
};

/*********************************************************************************
 * Update to websocket for server
 ********************************************************************************/
pump_lib bool upgrade_to_websocket(connection *conn, request_sptr &req);

}  // namespace http
}  // namespace proto
}  // namespace pump

#endif
