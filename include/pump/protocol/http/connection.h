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

#ifndef pump_protocol_http_connection_h
#define pump_protocol_http_connection_h

#include "pump/memory.h"
#include "pump/protocol/http/pocket.h"
#include "pump/transport/tcp_transport.h"

namespace pump {
namespace protocol {
    namespace http {

        class connection;
        DEFINE_ALL_POINTER_TYPE(connection);

        struct http_callbacks {
            // Http pocket callback
            pump_function<void(pocket_sptr &&pk)> pocket_cb;
            // Http connection error callback
            pump_function<void(const std::string &)> error_cb;
        };

        class LIB_PUMP connection 
          : public std::enable_shared_from_this<connection> {

          public:
            /*********************************************************************************
             * Constructor
             ********************************************************************************/
            connection(bool server, transport::base_transport_sptr &transp) noexcept;

            /*********************************************************************************
             * Deconstructor
             ********************************************************************************/
            virtual ~connection();

            /*********************************************************************************
             * Start http connection
             ********************************************************************************/
            bool start(service_ptr sv, const http_callbacks &cbs);

            /*********************************************************************************
             * Stop http connection
             ********************************************************************************/
            void stop();

            /*********************************************************************************
             * Read next http pocket
             ********************************************************************************/
            bool read_next_pocket();

            /*********************************************************************************
             * Send http pocket
             ********************************************************************************/
            bool send(c_pocket_ptr pk);

            /*********************************************************************************
             * Send http content
             ********************************************************************************/
            bool send(c_content_ptr ct);

            /*********************************************************************************
             * Check connection is valid or not
             ********************************************************************************/
            PUMP_INLINE transport::base_transport_sptr get_transport() {
                return transp_;
            }

            /*********************************************************************************
             * Check connection is valid or not
             ********************************************************************************/
            PUMP_INLINE transport::base_transport_sptr pop_transport() {
                return std::move(transp_);
            }

            /*********************************************************************************
             * Check connection is valid or not
             ********************************************************************************/
            PUMP_INLINE bool is_valid() const {
                return transp_ && transp_->is_started();
            }

          protected:
            /*********************************************************************************
             * Read event callback
             ********************************************************************************/
            static void on_read(connection_wptr wptr, const block_t *b, int32_t size);

            /*********************************************************************************
             * Disconnected event callback
             ********************************************************************************/
            static void on_disconnected(connection_wptr wptr);

            /*********************************************************************************
             * Stopped event callback
             ********************************************************************************/
            static void on_stopped(connection_wptr wptr);

          private:
            /*********************************************************************************
             * Handle http data
             ********************************************************************************/
            void __handle_http_data(const block_t *b, int32_t size);

            /*********************************************************************************
             * Stop transport
             ********************************************************************************/
            PUMP_INLINE void __stop_transport() {
                if (transp_) {
                    transp_->stop();
                }
            }

          private:
            // Read cache
            std::string read_cache_;

            // Coming http pocket
            pocket_sptr coming_pocket_;
            pump_function<pocket_ptr()> create_coming_pocket_;

            // Transport
            transport::base_transport_sptr transp_;

            // Http callbacks
            http_callbacks http_cbs_;
        };
        DEFINE_ALL_POINTER_TYPE(connection);

    }  // namespace http
}  // namespace protocol
}  // namespace pump

#endif
