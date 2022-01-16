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

    flow_tcp::flow_tcp() noexcept 
      : send_iob_(nullptr) {
    }

    flow_tcp::~flow_tcp() {
    }

    error_code flow_tcp::init(poll::channel_sptr &&ch, pump_socket fd) {
        if (!ch) {
            PUMP_WARN_LOG("channel is invalid");
            return ERROR_FAULT;
        }
        
        if (fd < 0) { 
            PUMP_WARN_LOG("socket fd is invalid");
            return ERROR_FAULT;
        }

        ch_ = ch;
        fd_ = fd;

        return ERROR_OK;
    }

    error_code flow_tcp::want_to_send(toolkit::io_buffer *iob) {
        if (iob == nullptr) { 
            PUMP_WARN_LOG("io buffer is invalid");
            return ERROR_FAULT;
        }
        send_iob_ = iob;
        
        int32_t size = net::send(fd_, send_iob_->data(), send_iob_->size());
        if (PUMP_LIKELY(size > 0)) {
            if (send_iob_->shift(size) == 0) {
                send_iob_ = nullptr;
                return ERROR_OK;
            }
            return ERROR_AGAIN;
        } else if (size < 0) {
            return ERROR_AGAIN;
        }

        PUMP_WARN_LOG("send buffer failed with ec %d", net::last_errno());

        return ERROR_FAULT;
    }

    error_code flow_tcp::send() {
        PUMP_ASSERT(send_iob_);
        PUMP_ASSERT(send_iob_->size() > 0);
        int32_t data_size = (int32_t)send_iob_->size();
        int32_t size = net::send(fd_, send_iob_->data(), data_size);
        if (PUMP_LIKELY(size > 0)) {
            if (send_iob_->shift(size) == 0) {
                send_iob_ = nullptr;
                return ERROR_OK;
            }
            return ERROR_AGAIN;
        } else if (size < 0) {
            return ERROR_AGAIN;
        }

        PUMP_WARN_LOG("send buffer failed with ec %d", net::last_errno());

        return ERROR_FAULT;
    }

}  // namespace flow
}  // namespace transport
}  // namespace pump
