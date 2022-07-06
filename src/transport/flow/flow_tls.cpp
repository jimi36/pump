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
    is_handshaked_(false),
    session_(nullptr),
    send_iob_(nullptr) {}

flow_tls::~flow_tls() {
    transport::delete_tls_session(session_);
}

error_code flow_tls::init(
    poll::channel_sptr &ch,
    bool client,
    pump_socket fd,
    transport::tls_credentials xcred) {
    if (!ch) {
        pump_warn_log("channel is invalid");
        return error_fault;
    }

    if (fd < 0) {
        pump_warn_log("socket fd is invalid");
        return error_fault;
    }

    session_ = transport::new_tls_session(client, fd, xcred);
    if (session_ == nullptr) {
        pump_warn_log("create tls session failed ");
        return error_fault;
    }

    ch_ = ch;
    fd_ = fd;

    return error_none;
}

error_code flow_tls::want_to_send(toolkit::io_buffer *iob) {
    if (iob == nullptr) {
        pump_warn_log("io buffer is invalid");
        return error_fault;
    }
    send_iob_ = iob;

    int32_t size =
        transport::tls_send(session_, send_iob_->data(), send_iob_->size());
    if (pump_likely(size > 0)) {
        // Shift send buffer and check data size.
        if (send_iob_->shift(size) > 0) {
            return error_again;
        }
        send_iob_->clear();
        send_iob_ = nullptr;
        return error_none;
    } else if (pump_unlikely(size < 0)) {
        // Send again
        return error_again;
    }

    pump_warn_log("send tls buffer failed with ec %d", net::last_errno());

    return error_fault;
}

error_code flow_tls::send() {
    pump_assert(send_iob_);
    int32_t size = transport::tls_send(
        session_,
        send_iob_->data(),
        send_iob_->size());
    if (pump_likely(size > 0)) {
        // Shift send buffer and check data size.
        if (send_iob_->shift(size) > 0) {
            return error_again;
        }
        send_iob_->clear();
        send_iob_ = nullptr;
        return error_none;
    } else if (pump_unlikely(size < 0)) {
        // Send again
        return error_again;
    }

    pump_warn_log("send tls buffer failed with ec %d", net::last_errno());

    return error_fault;
}

}  // namespace flow
}  // namespace transport
}  // namespace pump
