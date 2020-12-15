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
#if defined(PUMP_HAVE_IOCP)
            send_task_ = nullptr;
#endif
        }

        flow_tcp::~flow_tcp() {
#if defined(PUMP_HAVE_IOCP)
            if (send_task_) {
                send_task_->sub_link();
            }
#endif
        }

        flow_error flow_tcp::init(poll::channel_sptr &&ch, int32_t fd) {
            PUMP_DEBUG_ASSIGN(ch, ch_, ch);
            PUMP_DEBUG_ASSIGN(fd > 0, fd_, fd);

#if defined(PUMP_HAVE_IOCP)
            send_task_ = net::new_iocp_task();
            send_task_->set_fd(fd_);
            send_task_->set_notifier(ch_);
            send_task_->set_type(net::IOCP_TASK_SEND);
#endif
            return FLOW_ERR_NO;
        }

#if defined(PUMP_HAVE_IOCP)
        flow_error flow_tcp::post_read(net::iocp_task_ptr iocp_task) {
            if (!iocp_task) {
                auto iob = toolkit::io_buffer::create();
                iob->init_with_size(MAX_FLOW_BUFFER_SIZE);
                iocp_task = net::new_iocp_task();
                iocp_task->set_fd(fd_);
                iocp_task->set_notifier(ch_);
                iocp_task->set_type(net::IOCP_TASK_READ);
                iocp_task->bind_io_buffer(iob);
            } else {
                iocp_task->add_link();
            }
            if (!net::post_iocp_read(iocp_task)) {
                PUMP_WARN_LOG("flow_tcp::want_to_read: post iocp read failed");
                return FLOW_ERR_ABORT;
            }
            return FLOW_ERR_NO;
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
            int32_t size = iocp_task->get_processed_size();
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
            int32_t size = net::send(fd_, send_iob_->data(), send_iob_->data_size());
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

            int32_t data_size = (int32_t)send_iob_->data_size();
            if (data_size == 0) {
                return FLOW_ERR_NO_DATA;
            }

            int32_t size = net::send(fd_, send_iob_->data(), data_size);
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
