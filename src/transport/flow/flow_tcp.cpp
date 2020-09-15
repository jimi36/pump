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

        flow_tcp::flow_tcp() noexcept : send_buffer_(nullptr) {
#if defined(PUMP_HAVE_IOCP)
            read_task_ = nullptr;
            send_task_ = nullptr;
#endif
        }

        flow_tcp::~flow_tcp() {
#if defined(PUMP_HAVE_IOCP)
            if (read_task_)
                net::unlink_iocp_task(read_task_);
            if (send_task_)
                net::unlink_iocp_task(send_task_);
#endif
        }

        flow_error flow_tcp::init(poll::channel_sptr &&ch, int32 fd) {
            PUMP_DEBUG_ASSIGN(ch, ch_, ch);
            PUMP_DEBUG_ASSIGN(fd > 0, fd_, fd);

#if defined(PUMP_HAVE_IOCP)
            auto read_task = net::new_iocp_task();
            net::set_iocp_task_fd(read_task, fd_);
            net::set_iocp_task_notifier(read_task, ch_);
            net::set_iocp_task_type(read_task, IOCP_TASK_READ);
            net::set_iocp_task_buffer(read_task, read_cache_, sizeof(read_cache_));

            auto send_task = net::new_iocp_task();
            net::set_iocp_task_fd(send_task, fd_);
            net::set_iocp_task_notifier(send_task, ch_);
            net::set_iocp_task_type(send_task, IOCP_TASK_SEND);

            read_task_ = read_task;
            send_task_ = send_task;
#endif
            return FLOW_ERR_NO;
        }

#if defined(PUMP_HAVE_IOCP)
        flow_error flow_tcp::want_to_read() {
            net::reuse_iocp_task(read_task_);
            if (!net::post_iocp_read(read_task_)) {
                PUMP_WARN_LOG("flow::flow_tcp::want_to_read: post_iocp_read failed");
                return FLOW_ERR_ABORT;
            }
            return FLOW_ERR_NO;
        }
#endif

#if defined(PUMP_HAVE_IOCP)
        c_block_ptr flow_tcp::read(void_ptr iocp_task, int32_ptr size) {
            net::get_iocp_task_processed_data(iocp_task, size);
            return read_cache_;
        }
#else
        c_block_ptr flow_tcp::read(int32_ptr size) {
            *size = net::read(fd_, read_cache_, sizeof(read_cache_));
            return read_cache_;
        }
#endif

        flow_error flow_tcp::want_to_send(buffer_ptr sb) {
            PUMP_DEBUG_ASSIGN(sb, send_buffer_, sb);
#if defined(PUMP_HAVE_IOCP)
            net::set_iocp_task_buffer(
                send_task_, (block_ptr)send_buffer_->data(), send_buffer_->data_size());
            if (net::post_iocp_send(send_task_))
                return FLOW_ERR_NO;
#else
            int32 size = net::send(fd_, send_buffer_->data(), send_buffer_->data_size());
            if (PUMP_LIKELY(size > 0)) {
                send_buffer_->shift(size);
                return FLOW_ERR_NO;
            } else if (size < 0) {
                return FLOW_ERR_AGAIN;
            }
#endif
            return FLOW_ERR_ABORT;
        }

#if defined(PUMP_HAVE_IOCP)
        flow_error flow_tcp::send(void_ptr iocp_task) {
            int32 size = net::get_iocp_task_processed_size(iocp_task);
            if (size > 0) {
                PUMP_DEBUG_CHECK(send_buffer_->shift(size));
                auto data_size = send_buffer_->data_size();
                if (data_size == 0)
                    return FLOW_ERR_NO_DATA;

                net::set_iocp_task_buffer(
                    send_task_, (block_ptr)send_buffer_->data(), data_size);
                if (net::post_iocp_send(send_task_))
                    return FLOW_ERR_AGAIN;
            }
            return FLOW_ERR_ABORT;
        }
#else
        flow_error flow_tcp::send() {
            int32 data_size = (int32)send_buffer_->data_size();
            if (data_size == 0)
                return FLOW_ERR_NO_DATA;

            int32 size = net::send(fd_, send_buffer_->data(), data_size);
            if (PUMP_LIKELY(size > 0)) {
                send_buffer_->shift(size);
                if (data_size > size)
                    return FLOW_ERR_AGAIN;
                return FLOW_ERR_NO;
            } else if (size < 0) {
                return FLOW_ERR_AGAIN;
            }

            return FLOW_ERR_ABORT;
        }
#endif

    }  // namespace flow
}  // namespace transport
}  // namespace pump
