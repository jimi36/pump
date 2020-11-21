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
          : read_iob_(nullptr), 
            send_iob_(nullptr) {
#if defined(PUMP_HAVE_IOCP)
            read_task_ = nullptr;
            send_task_ = nullptr;
#endif
        }

        flow_tcp::~flow_tcp() {
#if defined(PUMP_HAVE_IOCP)
            if (read_task_) {
                read_task_->sub_link();
            }
            if (send_task_) {
                send_task_->sub_link();
            }
#endif
            if (read_iob_) {
                read_iob_->sub_ref();
            }
        }

        flow_error flow_tcp::init(poll::channel_sptr &&ch, int32 fd) {
            PUMP_DEBUG_ASSIGN(ch, ch_, ch);
            PUMP_DEBUG_ASSIGN(fd > 0, fd_, fd);

            read_iob_ = toolkit::io_buffer::create();
            read_iob_->init_with_size(MAX_FLOW_BUFFER_SIZE);

#if defined(PUMP_HAVE_IOCP)
            read_task_ = net::new_iocp_task();
            read_task_->set_fd(fd_);
            read_task_->set_notifier(ch_);
            read_task_->set_type(net::IOCP_TASK_READ);
            read_task_->bind_io_buffer(read_iob_);

            send_task_ = net::new_iocp_task();
            send_task_->set_fd(fd_);
            send_task_->set_notifier(ch_);
            send_task_->set_type(net::IOCP_TASK_SEND);
#endif
            return FLOW_ERR_NO;
        }

#if defined(PUMP_HAVE_IOCP)
        flow_error flow_tcp::post_read() {
            if (!net::post_iocp_read(read_task_)) {
                PUMP_WARN_LOG("flow_tcp::want_to_read: post iocp read failed");
                return FLOW_ERR_ABORT;
            }
            return FLOW_ERR_NO;
        }
#endif

#if defined(PUMP_HAVE_IOCP)
        c_block_ptr flow_tcp::read(net::iocp_task_ptr iocp_task, int32_ptr size) {
            *size = iocp_task->get_processed_size();
            return read_iob_->buffer();
        }
#else
        c_block_ptr flow_tcp::read(int32_ptr size) {
            block_ptr buf = (block_ptr)read_iob_->buffer();
            *size = net::read(fd_, buf, read_iob_->buffer_size());
            return buf;
        }
#endif



#if defined(PUMP_HAVE_IOCP)
        flow_error flow_tcp::post_send(toolkit::io_buffer_ptr iob) {
            PUMP_DEBUG_ASSIGN(iob, send_iob_, iob);
            send_task_->bind_io_buffer(send_iob_);
            if (net::post_iocp_send(send_task_)) {
                return FLOW_ERR_NO;
            }
            return FLOW_ERR_ABORT;
        }

        flow_error flow_tcp::send(net::iocp_task_ptr iocp_task) {
            int32 size = iocp_task->get_processed_size();
            if (size > 0) {
                if (PUMP_LIKELY(send_iob_->shift(size) == 0)) {
                    send_task_->unbind_io_buffer();
                    return FLOW_ERR_NO_DATA;
                }

                send_task_->update_io_buffer();
                if (net::post_iocp_send(send_task_)) {
                    return FLOW_ERR_AGAIN;
                }
            }
            return FLOW_ERR_ABORT;
        }
#else
        flow_error flow_tcp::want_to_send(toolkit::io_buffer_ptr iob) {
            PUMP_DEBUG_ASSIGN(iob, send_iob_, iob);
            int32 size = net::send(fd_, send_iob_->data(), send_iob_->data_size());
            if (PUMP_LIKELY(size > 0)) {
                if (PUMP_LIKELY(send_iob_->shift(size) == 0)) {
                    send_iob_ = nullptr;
                    return FLOW_ERR_NO;
                }
                return FLOW_ERR_AGAIN;
            }
            else if (size < 0) {
                return FLOW_ERR_AGAIN;
            }

            return FLOW_ERR_ABORT;
        }

        flow_error flow_tcp::send() {
            if (!send_iob_) {
                return FLOW_ERR_NO_DATA;
            }

            int32 data_size = (int32)send_iob_->data_size();
            if (data_size == 0) {
                return FLOW_ERR_NO_DATA;
            }

            int32 size = net::send(fd_, send_iob_->data(), data_size);
            if (PUMP_LIKELY(size > 0)) {
                if (PUMP_LIKELY(send_iob_->shift(size) > 0)) {
                    return FLOW_ERR_AGAIN;
                }
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
