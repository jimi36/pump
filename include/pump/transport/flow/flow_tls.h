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

#include "pump/transport/tls_utils.h"
#include "pump/transport/flow/flow.h"

namespace pump {
namespace transport {
namespace flow {

struct tls_session;
DEFINE_SMART_POINTERS(tls_session);

class flow_tls : public flow_base {
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
     *     error_none    => success
     *     error_fault => error
     ********************************************************************************/
    error_code init(
        poll::channel_sptr &ch,
        bool client,
        pump_socket fd,
        transport::tls_credentials xcred);

    /*********************************************************************************
     * Handshake
     * Return results:
     *     tls_handshake_ok
     *     tls_handshake_read
     *     tls_handshake_send
     *     tls_handshake_error
     ********************************************************************************/
    pump_inline int32_t handshake() {
        return transport::tls_handshake(session_);
    }

    /*********************************************************************************
     * Read
     ********************************************************************************/
    pump_inline int32_t read(char *b, int32_t size) {
        return transport::tls_read(session_, b, size);
    }

    /*********************************************************************************
     * Check there are data to read or not
     ********************************************************************************/
    pump_inline bool has_unread_data() const {
        return transport::tls_has_unread_data(session_);
    }

    /*********************************************************************************
     * Want to send
     * If using iocp this post an iocp task for sending, else this try sending
     * data. Return results:
     *     error_none    => send completely
     *     error_again   => try again
     *     error_fault   => error
     ********************************************************************************/
    error_code want_to_send(toolkit::io_buffer *iob);

    /*********************************************************************************
     * Send to net
     * Return results:
     *     error_none    => send completely
     *     error_again   => try again
     *     error_fault   => error
     ********************************************************************************/
    error_code send();

    /*********************************************************************************
     * Check there are data to send or not
     ********************************************************************************/
    pump_inline bool has_unsend_data() const {
        pump_assert(session_);
        return false;
    }

    /*********************************************************************************
     * Check handshaked status
     ********************************************************************************/
    pump_inline bool is_handshaked() const {
        return is_handshaked_;
    }

  private:
    // Handshaked status
    bool is_handshaked_;
    // TLS session
    transport::tls_session *session_;
    // Current sending io buffer
    toolkit::io_buffer *send_iob_;
};
DEFINE_SMART_POINTERS(flow_tls);

}  // namespace flow
}  // namespace transport
}  // namespace pump

#endif