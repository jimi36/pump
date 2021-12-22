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

#ifndef pump_protocol_websocket_server_h
#define pump_protocol_websocket_server_h

#include "pump/transport/tcp_acceptor.h"
#include "pump/transport/tls_acceptor.h"
#include "pump/protocol/websocket/connection.h"

namespace pump {
namespace protocol {
namespace websocket {

    class server;
    DEFINE_ALL_POINTER_TYPE(server);

    struct server_callbacks {
        // Check upgrade request callback
        pump_function<bool(const http::request*)> check_request_cb;
        // Upgraded callback
        pump_function<void(const std::string&, connection_sptr&)> upgraded_cb;
        // Error callback
        pump_function<void(const std::string&)> error_cb;
    };

    class LIB_PUMP server
      : public std::enable_shared_from_this<server> {

      public:
        typedef pump_function<service*()> get_service_callback;

        struct ws_upgarde_config {
            std::string host;
            std::string origin;
            std::string protoc;
        };

      public:
        /*********************************************************************************
         * Create instance
         ********************************************************************************/
        PUMP_INLINE static server_sptr create(
            const transport::address& listen_address,
            transport::tls_credentials xcred = nullptr) {
            INLINE_OBJECT_CREATE(obj, server, (listen_address, xcred));
            return server_sptr(obj, object_delete<server>);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~server() = default;

        /*********************************************************************************
         * Start
         ********************************************************************************/
        bool start(
            service *sv, 
            const server_callbacks &cbs);

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        void stop();

        /*********************************************************************************
         * Set select service callabck
         ********************************************************************************/
        PUMP_INLINE void set_select_service_callabck(const get_service_callback &cb) {
            select_service_cb_ = cb;
        }

      protected:
        /*********************************************************************************
         * Acceptor accepted callback
         ********************************************************************************/
        static void on_accepted(
            server_wptr wptr, 
            transport::base_transport_sptr &transp);

        /*********************************************************************************
         * Acceptor stopped callback
         ********************************************************************************/
        static void on_stopped(server_wptr wptr);

        /*********************************************************************************
         * Upgrade request callback
         ********************************************************************************/
        static void on_upgrade_request(
            server_wptr wptr,
            connection *conn,
            http::pocket_sptr pk);

        /*********************************************************************************
         * Connection error callback
         ********************************************************************************/
        static void on_error(
            server_wptr wptr,
            connection *conn,
            const std::string &msg);

      private:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        server(
            const transport::address &listen_address,
            transport::tls_credentials xcred) noexcept;

        /*********************************************************************************
         * Handle http upgrade request
         ********************************************************************************/
        bool __handle_upgrade_request(
            connection *conn, 
            http::request *req);

        /*********************************************************************************
         * Stop all upgrading connections
         ********************************************************************************/
        void __stop_all_upgrading_conns();

      private:
        // Service
        service *sv_;
        
        // Acceptor
        transport::base_acceptor_sptr acceptor_;

        // Select service callback
        get_service_callback select_service_cb_;

        // Connections
        std::mutex conn_mx_;
        std::map<void*, connection_sptr> conns_;

        // Callbacks
        server_callbacks cbs_;
    };

}  // namespace websocket
}  // namespace protocol
}  // namespace pump

#endif
