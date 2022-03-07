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

#include "pump/transport/flow/flow_tcp.h"

namespace pump {
namespace transport {
namespace flow {

flow_tcp::flow_tcp() noexcept :
    send_iob_(nullptr) {}

flow_tcp::~flow_tcp() {}

error_code flow_tcp::init(poll::channel_sptr &&ch, pump_socket fd) {
    if (!ch) {
        pump_warn_log("channel is invalid");
        return error_fault;
    }

    if (fd < 0) {
        pump_warn_log("socket fd is invalid");
        return error_fault;
    }

    ch_ = ch;
    fd_ = fd;

    return error_none;
}

error_code flow_tcp::want_to_send(toolkit::io_buffer *iob) {
    if (iob == nullptr) {
        pump_warn_log("io buffer is invalid");
        return error_fault;
    }
    send_iob_ = iob;

    int32_t size = net::send(fd_, send_iob_->data(), send_iob_->size());
    if (pump_likely(size > 0)) {
        if (send_iob_->shift(size) == 0) {
            send_iob_ = nullptr;
            return error_none;
        }
        return error_again;
    } else if (size < 0) {
        return error_again;
    }

    pump_warn_log("send buffer failed with ec %d", net::last_errno());

    return error_fault;
}

error_code flow_tcp::send() {
    pump_assert(send_iob_);
    pump_assert(send_iob_->size() > 0);
    int32_t data_size = (int32_t)send_iob_->size();
    int32_t size = net::send(fd_, send_iob_->data(), data_size);
    if (pump_likely(size > 0)) {
        if (send_iob_->shift(size) == 0) {
            send_iob_ = nullptr;
            return error_none;
        }
        return error_again;
    } else if (size < 0) {
        return error_again;
    }

    pump_warn_log("send buffer failed with ec %d", net::last_errno());

    return error_fault;
}

}  // namespace flow
}  // namespace transport
}  // namespace pump
