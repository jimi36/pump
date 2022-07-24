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

#ifndef pump_proto_http_client_h
#define pump_proto_http_client_h

#include "pump/toolkit/features.h"
#include "pump/proto/http/request.h"
#include "pump/proto/http/response.h"
#include "pump/proto/http/connection.h"

namespace pump {
namespace proto {
namespace http {

using transport::address;

class client;
DEFINE_SMART_POINTERS(client);

class pump_lib client
  : public toolkit::noncopyable,
    public std::enable_shared_from_this<client> {
  public:
    /*********************************************************************************
     * Create instance
     ********************************************************************************/
    pump_inline static client_sptr create(service *sv) {
        INLINE_OBJECT_CREATE(obj, client, (sv));
        return client_sptr(obj, object_delete<client>);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~client() = default;

    /*********************************************************************************
     * Set connect timeout time
     ********************************************************************************/
    pump_inline void set_connect_timeout(int64_t timeout) pump_noexcept {
        dial_timeout_ = timeout > 0 ? timeout : 0;
    }

    /*********************************************************************************
     * Set tls handshake timeout time
     ********************************************************************************/
    pump_inline void set_tls_handshake_timeout(int64_t timeout) pump_noexcept {
        tls_handshake_timeout_ = timeout > 0 ? timeout : 0;
    }

    /*********************************************************************************
     * Do request
     * At first this will create http connection if there no valid http
     *connection, then send http request to http server.
     ********************************************************************************/
    response_sptr do_request(request_sptr &req);

    /*********************************************************************************
     * Open websocket connection
     ********************************************************************************/
    connection_sptr open_websocket(const std::string &url);

    /*********************************************************************************
     * Close
     ********************************************************************************/
    pump_inline void close() {
        __destroy_connection();
    }

  private:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    client(service *sv) pump_noexcept;

    /*********************************************************************************
     * Setup http connection and listen http response
     ********************************************************************************/
    bool __async_read_http_response(const uri *u);

    /*********************************************************************************
     * Destroy http connection
     ********************************************************************************/
    void __destroy_connection();

    /*********************************************************************************
     * Send websocket upgrade request
     ********************************************************************************/
    bool __send_websocket_upgrade_request(
        const std::string &url,
        std::map<std::string, std::string> &headers);

    /*********************************************************************************
     * Handle websocket upgrade response
     ********************************************************************************/
    bool __handle_websocket_upgrade_response(response_sptr &rsp);

    /*********************************************************************************
     * Destroy http connection
     ********************************************************************************/
    void __notify_response(connection *conn, response_sptr &&resp);

  private:
    /*********************************************************************************
     * Handel connection response
     ********************************************************************************/
    static void on_response(
        client_wptr cli,
        connection *conn,
        packet_sptr &pk);

    /*********************************************************************************
     * Handel connection disconnected
     ********************************************************************************/
    static void on_error(
        client_wptr cli,
        connection *conn,
        const std::string &msg);

  private:
    // Service
    service *sv_;

    // Dial timeout ms tims
    int64_t dial_timeout_;
    // TLS handshake timeout ms time
    int64_t tls_handshake_timeout_;

    // Http connection
    connection_sptr conn_;

    // Last request uri
    uri last_uri_;

    // Response condition
    std::mutex resp_mx_;
    std::condition_variable resp_cond_;
    bool wait_for_response_;

    // Response
    response_sptr resp_;
};

}  // namespace http
}  // namespace proto
}  // namespace pump

#endif
