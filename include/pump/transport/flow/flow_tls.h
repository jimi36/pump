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

#include "pump/ssl/tls_helper.h"
#include "pump/transport/flow/flow.h"

namespace pump {
namespace transport {
    namespace flow {

        struct tls_session;
        DEFINE_ALL_POINTER_TYPE(tls_session);

        class ssl_net_layer;

        class flow_tls 
          : public flow_base {

          public:
            friend class ssl_net_layer;

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
                         int32_t fd,
                         void_ptr xcred,
                         bool client);

            /*********************************************************************************
             * Rebind channel
             ********************************************************************************/
            void rebind_channel(poll::channel_sptr &ch);

            /*********************************************************************************
             * Handshake
             * Return results:
             *     FLOW_ERR_NO    => handshake success, no mean finished completely
             *     FLOW_ERR_ABORT => handshake error
             ********************************************************************************/
            int32_t handshake();

#if defined(PUMP_HAVE_IOCP)
            /*********************************************************************************
             * Post read
             * If using IOCP this post a IOCP task for reading, else do nothing.
             * Return results:
             *     FLOW_ERR_BUSY  => busy for read
             *     FLOW_ERR_NO    => success
             *     FLOW_ERR_ABORT => error
             ********************************************************************************/
            int32_t post_read();
#endif
            /*********************************************************************************
             * Read from net
             * Return results:
             *     FLOW_ERR_NO    => success
             *     FLOW_ERR_AGAIN => no more data on net
             *     FLOW_ERR_ABORT => error
             ********************************************************************************/
#if defined(PUMP_HAVE_IOCP)
            int32_t read_from_net(net::iocp_task_ptr iocp_task);
#else
            int32_t read_from_net();
#endif
            /*********************************************************************************
             * Read from ssl
             ********************************************************************************/
            int32_t read_from_ssl(block_t *b, int32_t size);

            /*********************************************************************************
             * Check there are data to read or not
             ********************************************************************************/
            PUMP_INLINE bool has_data_to_read() const {
                PUMP_ASSERT(session_);
                return session_->has_data_pending();
            }

            /*********************************************************************************
             * Send to ssl
             * Return results:
             *     FLOW_ERR_NO      => success
             *     FLOW_ERR_ABORT   => error
             ********************************************************************************/
            int32_t send_to_ssl(toolkit::io_buffer_ptr iob);

#if defined(PUMP_HAVE_IOCP)
            /*********************************************************************************
             * Post send
             * Return results:
             *     FLOW_ERR_NO      => success
             *     FLOW_ERR_ABORT   => error
             ********************************************************************************/
            int32_t post_send();
#else
            /*********************************************************************************
             * Want to send
             * If using iocp this post an iocp task for sending, else this try sending
             * data. Return results:
             *     FLOW_ERR_NO      => success
             *     FLOW_ERR_NO_DATA => no
             *     FLOW_ERR_ABORT   => error
             ********************************************************************************/
            int32_t want_to_send();
#endif
            /*********************************************************************************
             * Send to net
             * Return results:
             *     FLOW_ERR_NO      => send completely
             *     FLOW_ERR_AGAIN   => try to send again
             *     FLOW_ERR_NO_DATA => no data to send
             *     FLOW_ERR_ABORT   => error
             ********************************************************************************/
#if defined(PUMP_HAVE_IOCP)
            int32_t send_to_net(net::iocp_task_ptr iocp_task);
#else
            int32_t send_to_net();
#endif
            /*********************************************************************************
             * Check there are data to send or not
             ********************************************************************************/
            PUMP_INLINE bool has_data_to_send() const {
                PUMP_ASSERT(session_);
                return session_->get_net_send_buffer()->data_size() > 0;
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

#if defined(PUMP_HAVE_IOCP)
            // IOCP read task
            net::iocp_task_ptr read_task_;
            // IOCP send task
            net::iocp_task_ptr send_task_;
#endif
        };
        DEFINE_ALL_POINTER_TYPE(flow_tls);

    }  // namespace flow
}  // namespace transport
}  // namespace pump

#endif