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

#ifndef pump_transport_flow_tls_h
#define pump_transport_flow_tls_h

#include "pump/ssl/tls.h"
#include "pump/transport/flow/flow.h"

namespace pump {
namespace transport {
namespace flow {

    struct tls_session;
    DEFINE_ALL_POINTER_TYPE(tls_session);

    class flow_tls 
      : public flow_base {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        flow_tls() noexcept;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~flow_tls();

        /*********************************************************************************
         * Init flow
         * Return results:
         *     FLOW_ERR_NO    => success
         *     FLOW_ERR_ABORT => error
         ********************************************************************************/
        int32_t init(poll::channel_sptr &ch,
                     pump_socket fd,
                     void_ptr xcred,
                     bool client);

        /*********************************************************************************
         * Handshake
         * Return results:
         *     TLS_HANDSHAKE_OK
         *     TLS_HANDSHAKE_READ
         *     TLS_HANDSHAKE_SEND
         *     TLS_HANDSHAKE_ERROR
         ********************************************************************************/
        PUMP_INLINE int32_t handshake() {
            return ssl::tls_handshake(session_);
        }

        /*********************************************************************************
         * Read
         ********************************************************************************/
        PUMP_INLINE int32_t read(block_t* b, int32_t size) {
            return ssl::tls_read(session_, b, size);
        }

        /*********************************************************************************
         * Check there are data to read or not
         ********************************************************************************/
        PUMP_INLINE bool has_unread_data() const {
            PUMP_ASSERT(session_);
            return ssl::tls_has_unread_data(session_);
        }

        /*********************************************************************************
         * Want to send
         * If using iocp this post an iocp task for sending, else this try sending
         * data. Return results:
         *     FLOW_ERR_NO      => send completely
         *     FLOW_ERR_AGAIN   => try again
         *     FLOW_ERR_ABORT   => error
         ********************************************************************************/
        int32_t want_to_send(toolkit::io_buffer_ptr iob);

        /*********************************************************************************
         * Send to net
         * Return results:
         *     FLOW_ERR_NO      => send completely
         *     FLOW_ERR_AGAIN   => try again
         *     FLOW_ERR_NO_DATA => no data for sending
         *     FLOW_ERR_ABORT   => error
         ********************************************************************************/
        int32_t send();

        /*********************************************************************************
         * Check there are data to send or not
         ********************************************************************************/
        PUMP_INLINE bool has_unsend_data() const {
            PUMP_ASSERT(session_);
            return false;
        }

        /*********************************************************************************
         * Check handshaked status
         ********************************************************************************/
        PUMP_INLINE bool is_handshaked() const {
            return is_handshaked_;
        }

        private:
        // Handshaked status
        bool is_handshaked_;
        // TLS session
        ssl::tls_session_ptr session_;
        // Current sending io buffer
        toolkit::io_buffer_ptr send_iob_;
    };
    DEFINE_ALL_POINTER_TYPE(flow_tls);

}  // namespace flow
}  // namespace transport
}  // namespace pump

#endif