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

flow_tls::flow_tls() noexcept :
    is_handshaked_(false), session_(nullptr), send_iob_(nullptr) {}

flow_tls::~flow_tls() {
    transport::delete_tls_session(session_);
}

error_code flow_tls::init(poll::channel_sptr &ch,
                          bool client,
                          pump_socket fd,
                          transport::tls_credentials xcred) {
    if (!ch) {
        PUMP_WARN_LOG("channel is invalid");
        return ERROR_FAULT;
    }

    if (fd < 0) {
        PUMP_WARN_LOG("socket fd is invalid");
        return ERROR_FAULT;
    }

    session_ = transport::new_tls_session(client, fd, xcred);
    if (session_ == nullptr) {
        PUMP_WARN_LOG("create tls session failed ");
        return ERROR_FAULT;
    }

    ch_ = ch;
    fd_ = fd;

    return ERROR_OK;
}

error_code flow_tls::want_to_send(toolkit::io_buffer *iob) {
    if (iob == nullptr) {
        PUMP_WARN_LOG("io buffer is invalid");
        return ERROR_FAULT;
    }
    send_iob_ = iob;

    int32_t size =
        transport::tls_send(session_, send_iob_->data(), send_iob_->size());
    if (pump_likely(size > 0)) {
        // Shift send buffer and check data size.
        if (send_iob_->shift(size) > 0) {
            return ERROR_AGAIN;
        }
        send_iob_->clear();
        send_iob_ = nullptr;
        return ERROR_OK;
    } else if (pump_unlikely(size < 0)) {
        // Send again
        return ERROR_AGAIN;
    }

    PUMP_WARN_LOG("send tls buffer failed with ec %d", net::last_errno());

    return ERROR_FAULT;
}

error_code flow_tls::send() {
    PUMP_ASSERT(send_iob_);
    int32_t size =
        transport::tls_send(session_, send_iob_->data(), send_iob_->size());
    if (pump_likely(size > 0)) {
        // Shift send buffer and check data size.
        if (send_iob_->shift(size) > 0) {
            return ERROR_AGAIN;
        }
        send_iob_->clear();
        send_iob_ = nullptr;
        return ERROR_OK;
    } else if (pump_unlikely(size < 0)) {
        // Send again
        return ERROR_AGAIN;
    }

    PUMP_WARN_LOG("send tls buffer failed with ec %d", net::last_errno());

    return ERROR_FAULT;
}

}  // namespace flow
}  // namespace transport
}  // namespace pump
