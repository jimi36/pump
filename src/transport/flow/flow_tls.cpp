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
            session_(nullptr) {
#if defined(PUMP_HAVE_IOCP)
            read_task_ = nullptr;
            send_task_ = nullptr;
#endif
        }

        flow_tls::~flow_tls() {
            ssl::destory_tls_session(session_);
#if defined(PUMP_HAVE_IOCP)
            if (read_task_) {
                read_task_->sub_link();
            }
            if (send_task_) {
                send_task_->sub_link();
            }
#endif
        }

        int32_t flow_tls::init(poll::channel_sptr &ch,
                               int32_t fd,
                               void_ptr xcred,
                               bool client) {
            PUMP_DEBUG_ASSIGN(ch, ch_, ch);
            PUMP_DEBUG_ASSIGN(fd > 0, fd_, fd);

            session_ = ssl::create_tls_session(xcred, client, MAX_TCP_BUFFER_SIZE);
            if (!session_) {
                return FLOW_ERR_ABORT;
            }

#if defined(PUMP_HAVE_IOCP)
            read_task_ = net::new_iocp_task();
            read_task_->set_fd(fd_);
            read_task_->set_notifier(ch_);
            read_task_->set_type(net::IOCP_TASK_READ);
            read_task_->bind_io_buffer(session_->get_net_read_buffer());

            send_task_ = net::new_iocp_task();
            send_task_->set_fd(fd_);
            send_task_->set_notifier(ch_);
            send_task_->set_type(net::IOCP_TASK_SEND);
            send_task_->bind_io_buffer(session_->get_net_send_buffer());
#endif
            return FLOW_ERR_NO;
        }

        void flow_tls::rebind_channel(poll::channel_sptr &ch) {
#if defined(PUMP_HAVE_IOCP)
            PUMP_DEBUG_ASSIGN(ch, ch_, ch);
            read_task_->set_notifier(ch_);
            send_task_->set_notifier(ch_);
#endif
        }

        int32_t flow_tls::handshake() {
            if (is_handshaked_) {
                return FLOW_ERR_NO;
            }

            int32_t ret = ssl::tls_handshake(session_);
            if (ret == 0) {
                is_handshaked_ = true;
                return FLOW_ERR_NO;
            } else if (ret == 1) {
                return FLOW_ERR_NO;
            }

            return FLOW_ERR_ABORT;
        }

#if defined(PUMP_HAVE_IOCP)
        int32_t flow_tls::post_read() {
            if (PUMP_LIKELY(net::post_iocp_read(read_task_))) {
                return FLOW_ERR_NO;
            }

            PUMP_WARN_LOG("flow_tls::want_to_read: failed");
            return FLOW_ERR_ABORT;
        }
#endif

#if defined(PUMP_HAVE_IOCP)
        int32_t flow_tls::read_from_net(net::iocp_task_ptr iocp_task) {
            int32_t size = iocp_task->get_processed_size();
            if (PUMP_LIKELY(size > 0)) {
                session_->reset_read_data_size(size);
                return FLOW_ERR_NO;
            }

            PUMP_WARN_LOG("flow_tls::read_from_net: failed");
            return FLOW_ERR_ABORT;
        }
#else
        int32_t flow_tls::read_from_net() {
            toolkit::io_buffer *read_iob = session_->get_net_read_buffer();
            int32_t size = net::read(fd_, read_iob->buffer(), read_iob->buffer_size());
            if (PUMP_LIKELY(size > 0)) {
                session_->reset_read_data_size(size);
                return FLOW_ERR_NO;
            } else if (PUMP_UNLIKELY(size < 0)) {
                return FLOW_ERR_AGAIN;
            }

            PUMP_WARN_LOG("flow_tls::read_from_net: failed");
            return FLOW_ERR_ABORT;
        }
#endif

        int32_t flow_tls::read_from_ssl(block_t *b, int32_t size) {
            int32_t ret = ssl::tls_read(session_, b, size);
            if (ret > 0) {
                return ret;
            } else if (ret < 0) {
                return -1;
            }

            PUMP_WARN_LOG("flow_tls::read_from_net: failed %d", ret);
            return 0;
        }

        int32_t flow_tls::send_to_ssl(toolkit::io_buffer_ptr iob) {
            PUMP_ASSERT(iob && iob->data_size() > 0);
            do {
                int32_t size = ssl::tls_send(session_, iob->data(), iob->data_size());
                if (size <= 0) {
                    break;
                }
                if (PUMP_LIKELY(iob->shift(size) == 0)) {
                    return FLOW_ERR_NO;
                }
            } while (true);

            return FLOW_ERR_ABORT;
        }

#if defined(PUMP_HAVE_IOCP)
        int32_t flow_tls::post_send() {
            send_task_->update_io_buffer();
            if (net::post_iocp_send(send_task_)) {
                return FLOW_ERR_NO;
            }
            return FLOW_ERR_ABORT;
        }

        int32_t flow_tls::send_to_net(net::iocp_task_ptr iocp_task) {
            // net send buffer must has data when using iocp
            toolkit::io_buffer *send_iob = session_->get_net_send_buffer();
            PUMP_ASSERT(send_iob->data_size() > 0);

            int32_t size = iocp_task->get_processed_size();
            if (PUMP_LIKELY(size > 0)) {
                // Shift send buffer and check data size.
                if (send_iob->shift(size) > 0) {
                    send_task_->update_io_buffer();
                    if (!net::post_iocp_send(send_task_)) {
                        PUMP_WARN_LOG("flow_tls::send_to_net: post iocp send failed");
                        return FLOW_ERR_ABORT;
                    }
                    return FLOW_ERR_AGAIN;
                }

                // Io buffer sent finished.
                send_iob->reset();

                return FLOW_ERR_NO;
            }

            PUMP_WARN_LOG("flow_tls::send_to_net: failed");
            return FLOW_ERR_ABORT;
        }
#else
        int32_t flow_tls::want_to_send() {
            toolkit::io_buffer *send_iob = session_->get_net_send_buffer();
            int32_t size = net::send(fd_, send_iob->buffer(), send_iob->data_size());
            if (PUMP_LIKELY(size > 0)) {
                // Shift send buffer and check data size.
                if (send_iob->shift(size) > 0) {
                    return FLOW_ERR_AGAIN;
                }

                // Send finish, reset send buffer
                send_iob->reset();

                return FLOW_ERR_NO;
            }
            else if (PUMP_UNLIKELY(size < 0)) {
                // Send again
                return FLOW_ERR_AGAIN;
            }

            PUMP_WARN_LOG("flow_tls::want_to_send: failed");
            return FLOW_ERR_ABORT;
        }

        int32_t flow_tls::send_to_net() {
            toolkit::io_buffer *send_iob = session_->get_net_send_buffer();
            uint32_t data_size = send_iob->data_size();
            if (data_size == 0) {
                return FLOW_ERR_NO;
            }

            int32_t size = net::send(fd_, send_iob->data(), data_size);
            if (PUMP_LIKELY(size > 0)) {
                // Shift send buffer and check data size.
                if (send_iob->shift(size) > 0) {
                    return FLOW_ERR_AGAIN;
                }

                // Io buffer sent finished.
                send_iob->reset();

                return FLOW_ERR_NO;
            } else if (PUMP_UNLIKELY(size < 0)) {
                // Try to send again.
                return FLOW_ERR_AGAIN;
            }

            PUMP_WARN_LOG("flow_tls::send_to_net: failed");
            return FLOW_ERR_ABORT;
        }
#endif

    }  // namespace flow
}  // namespace transport
}  // namespace pump
