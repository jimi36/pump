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

#include "pump/transport/flow/flow_tls.h"

namespace pump {
namespace transport {
namespace flow {

    flow_tls::flow_tls() noexcept
      : is_handshaked_(false),
        session_(nullptr),
        send_iob_(nullptr){
    }

    flow_tls::~flow_tls() {
        ssl::destory_tls_session(session_);
    }

    int32_t flow_tls::init(
        poll::channel_sptr &ch,
        pump_socket fd,
        void *xcred,
        bool client) {
        PUMP_DEBUG_ASSIGN(ch, ch_, ch);
        PUMP_DEBUG_ASSIGN(fd > 0, fd_, fd);

        session_ = ssl::create_tls_session(xcred, (int32_t)fd, client);
        if (!session_) {
            return FLOW_ERR_ABORT;
        }

        return FLOW_ERR_NO;
    }

    int32_t flow_tls::want_to_send(toolkit::io_buffer_ptr iob) {
        PUMP_DEBUG_ASSIGN(iob, send_iob_, iob);
        int32_t size = ssl::tls_send(session_, send_iob_->buffer(), send_iob_->data_size());
        if (PUMP_LIKELY(size > 0)) {
            // Shift send buffer and check data size.
            if (send_iob_->shift(size) > 0) {
                return FLOW_ERR_AGAIN;
            }

            send_iob_->reset();

            return FLOW_ERR_NO;
        } else if (PUMP_UNLIKELY(size < 0)) {
            // Send again
            return FLOW_ERR_AGAIN;
        }

        PUMP_DEBUG_LOG("flow_tls: want to send failed");

        return FLOW_ERR_ABORT;
    }

    int32_t flow_tls::send() {
        PUMP_ASSERT(send_iob_);
        int32_t size = ssl::tls_send(session_, send_iob_->buffer(), send_iob_->data_size());
        if (PUMP_LIKELY(size > 0)) {
            // Shift send buffer and check data size.
            if (send_iob_->shift(size) > 0) {
                return FLOW_ERR_AGAIN;
            }

            send_iob_->reset();

            return FLOW_ERR_NO;
        } else if (PUMP_UNLIKELY(size < 0)) {
            // Send again
            return FLOW_ERR_AGAIN;
        }

        PUMP_DEBUG_LOG("flow_tls: send failed");

        return FLOW_ERR_ABORT;
    }

}  // namespace flow
}  // namespace transport
}  // namespace pump
