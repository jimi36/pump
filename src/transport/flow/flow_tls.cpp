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
    send_iob_(nullptr) {
}

flow_tls::~flow_tls() {
    transport::delete_tls_session(session_);
}

bool flow_tls::init(
    poll::channel_sptr &ch,
    bool client,
    pump_socket fd,
    transport::tls_credentials xcred) {
    if (!ch) {
        pump_debug_log("channel invalid");
        return false;
    }
    if (fd < 0) {
        pump_debug_log("socket fd invalid");
        return false;
    }

    session_ = transport::new_tls_session(client, fd, xcred);
    if (session_ == nullptr) {
        pump_debug_log("create tls session object failed ");
        return false;
    }

    ch_ = ch;
    fd_ = fd;

    return true;
}

error_code flow_tls::want_to_send(toolkit::io_buffer *iob) {
    if (iob == nullptr || send_iob_ != nullptr) {
        return error_fault;
    }
    send_iob_ = iob;
    return send();
}

error_code flow_tls::send() {
    auto size = transport::tls_send(
        session_,
        send_iob_->data(),
        send_iob_->size());
    if (size == 0) {
        return error_fault;
    } else if (size < 0) {
        return error_again;
    }

    if (send_iob_->shift(size) > 0) {
        return error_again;
    }
    send_iob_ = nullptr;

    return error_none;
}

}  // namespace flow
}  // namespace transport
}  // namespace pump
