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

        int32_t flow_tcp::init(poll::channel_sptr &&ch, pump_socket fd) {
            PUMP_DEBUG_ASSIGN(ch, ch_, ch);
            PUMP_DEBUG_ASSIGN(fd > 0, fd_, fd);
            return FLOW_ERR_NO;
        }

        int32_t flow_tcp::want_to_send(toolkit::io_buffer_ptr iob) {
            PUMP_DEBUG_ASSIGN(iob, send_iob_, iob);
            int32_t size = net::send(fd_, send_iob_->data(), send_iob_->data_size());
            if (PUMP_LIKELY(size > 0)) {
                if (PUMP_LIKELY(send_iob_->shift(size) == 0)) {
                    send_iob_ = nullptr;
                    return FLOW_ERR_NO;
                }
                return FLOW_ERR_AGAIN;
            } else if (size < 0) {
                return FLOW_ERR_AGAIN;
            }

            PUMP_DEBUG_LOG("flow_tcp: want to send failed %d", size);

            return FLOW_ERR_ABORT;
        }

        int32_t flow_tcp::send() {
            PUMP_ASSERT(send_iob_);
            PUMP_ASSERT(send_iob_->data_size() > 0);
            int32_t data_size = (int32_t)send_iob_->data_size();
            int32_t size = net::send(fd_, send_iob_->data(), data_size);
            if (PUMP_LIKELY(size > 0)) {
                if (send_iob_->shift(size) == 0) {
                    send_iob_ = nullptr;
                    return FLOW_ERR_NO;
                }
                return FLOW_ERR_AGAIN;
            } else if (size < 0) {
                return FLOW_ERR_AGAIN;
            }

            PUMP_DEBUG_LOG("flow_tcp: send failed %d", size);

            return FLOW_ERR_ABORT;
        }

    }  // namespace flow
}  // namespace transport
}  // namespace pump
