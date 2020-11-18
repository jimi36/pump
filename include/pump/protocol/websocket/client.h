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
#ifndef pump_protocol_websocket_client_h
#define pump_protocol_websocket_client_h

#include "pump/protocol/http/client.h"
#include "pump/transport/base_dialer.h"
#include "pump/protocol/websocket/connection.h"

namespace pump {
namespace protocol {
    namespace websocket {

        class client;
        DEFINE_ALL_POINTER_TYPE(client);

        struct client_callbacks {
            // Started callback
            pump_function<void()> started_cb;
            // Data callback
            pump_function<void(c_block_ptr, uint32, bool)> data_cb;
            // Error callback
            pump_function<void(const std::string &)> error_cb;
        };

        class LIB_PUMP client : public std::enable_shared_from_this<client> {
          public:
            /*********************************************************************************
             * Create instance
             ********************************************************************************/
            PUMP_INLINE static client_sptr create() {
                INLINE_OBJECT_CREATE(obj, client, ());
                return client_sptr(obj, object_delete<client>);
            }

            /*********************************************************************************
             * Deconstructor
             ********************************************************************************/
            virtual ~client() = default;

            /*********************************************************************************
             * Start
             * This will try to create a websocket connection with the upgrade config.
             ********************************************************************************/
            bool start(service_ptr sv,
                       const client_callbacks &cbs,
                       const std::string &url,
                       const std::map<std::string, std::string> &headers);

            /*********************************************************************************
             * Stop
             ********************************************************************************/
            void stop();

            /*********************************************************************************
             * Send
             ********************************************************************************/
            bool send(c_block_ptr b, uint32 size);

          protected:
            /*********************************************************************************
             * Dialed callback
             ********************************************************************************/
            static void on_dialed(client_wptr wptr,
                                  transport::base_transport_sptr &transp,
                                  bool succ);

            /*********************************************************************************
             * Dialed timeout callback
             ********************************************************************************/
            static void on_dial_timeouted(client_wptr wptr);

            /*********************************************************************************
             * Stopped dialing callback
             ********************************************************************************/
            static void on_dial_stopped(client_wptr wptr);

          protected:
            /*********************************************************************************
             * Upgrade response callback
             ********************************************************************************/
            static void on_upgrade_response(client_wptr wptr, http::pocket_sptr pk);

            /*********************************************************************************
             * Frame callback
             ********************************************************************************/
            static void on_frame(client_wptr wptr, c_block_ptr b, uint32 size, bool end);

            /*********************************************************************************
             * Connection error closed
             ********************************************************************************/
            static void on_error(client_wptr wptr, const std::string &msg);

          private:
            /*********************************************************************************
             * Constructor
             ********************************************************************************/
            client() noexcept;

            /*********************************************************************************
             * Start dial and upgrade
             ********************************************************************************/
            bool __start(const std::string &url,
                         const std::map<std::string, std::string> &headers);

            /*********************************************************************************
             * Check http upgrade response
             ********************************************************************************/
            bool __check_upgrade_response(http::response_sptr &resp);

          private:
            // Started state
            std::atomic_bool started_;

            // Service
            service_ptr sv_;

            // Transport Dialer
            transport::base_dialer_sptr dialer_;

            // Websocket connection
            connection_sptr conn_;

            // Upgrade info
            bool upgraded_;
            http::request_sptr upgrade_req_;

            // Client callbacks
            client_callbacks cbs_;
        };

    }  // namespace websocket
}  // namespace protocol
}  // namespace pump

#endif