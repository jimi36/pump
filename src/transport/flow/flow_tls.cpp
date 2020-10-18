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
              read_task_(nullptr),
              send_task_(nullptr) {
        }

        flow_tls::~flow_tls() {
            ssl::destory_tls_session(session_);
#if defined(PUMP_HAVE_IOCP)
            if (read_task_) {
                net::unlink_iocp_task(read_task_);
            }
            if (send_task_) {
                net::unlink_iocp_task(send_task_);
            }
#endif
        }

        flow_error flow_tls::init(poll::channel_sptr &ch,
                                  int32 fd,
                                  void_ptr xcred,
                                  bool client) {
            PUMP_DEBUG_ASSIGN(ch, ch_, ch);
            PUMP_DEBUG_ASSIGN(fd > 0, fd_, fd);

            session_ = ssl::create_tls_session(xcred, client, MAX_FLOW_BUFFER_SIZE);
            if (!session_) {
                return FLOW_ERR_ABORT;
            }

#if defined(PUMP_HAVE_IOCP)
            auto read_task = net::new_iocp_task();
            net::set_iocp_task_fd(read_task, fd_);
            net::set_iocp_task_notifier(read_task, ch_);
            net::set_iocp_task_type(read_task, IOCP_TASK_READ);
            net::bind_iocp_task_buffer(read_task, session_->net_read_iob);

            auto send_task = net::new_iocp_task();
            net::set_iocp_task_fd(send_task, fd_);
            net::set_iocp_task_notifier(send_task, ch_);
            net::set_iocp_task_type(send_task, IOCP_TASK_SEND);
            net::bind_iocp_task_buffer(send_task, session_->net_send_iob);

            read_task_ = read_task;
            send_task_ = send_task;
#endif
            return FLOW_ERR_NO;
        }

        void flow_tls::rebind_channel(poll::channel_sptr &ch) {
#if defined(PUMP_HAVE_IOCP)
            PUMP_DEBUG_ASSIGN(ch, ch_, ch);
            net::set_iocp_task_notifier(read_task_, ch_);
            net::set_iocp_task_notifier(send_task_, ch_);
#endif
        }

        flow_error flow_tls::handshake() {
            if (is_handshaked_) {
                return FLOW_ERR_NO;
            }

            int32 ret = ssl::tls_handshake(session_);
            if (ret == 0) {
                is_handshaked_ = true;
                return FLOW_ERR_NO;
            } else if (ret == 1) {
                return FLOW_ERR_NO;
            }

            return FLOW_ERR_ABORT;
        }

#if defined(PUMP_HAVE_IOCP)
        flow_error flow_tls::want_to_read() {
            if (PUMP_LIKELY(net::post_iocp_read(read_task_))) {
                return FLOW_ERR_NO;
            }

            PUMP_WARN_LOG("flow_tls::want_to_read: failed");
            return FLOW_ERR_ABORT;
        }
#endif

#if defined(PUMP_HAVE_IOCP)
        flow_error flow_tls::read_from_net(void_ptr iocp_task) {
            int32 size = net::get_iocp_task_processed_size(iocp_task);
            if (PUMP_LIKELY(size > 0)) {
                session_->net_read_data_size = size;
                session_->net_read_data_pos = 0;
                return FLOW_ERR_NO;
            }

            PUMP_WARN_LOG("flow_tls::read_from_net: failed");
            return FLOW_ERR_ABORT;
        }
#else
        flow_error flow_tls::read_from_net() {
            int32 size = net::read(fd_,
                                   (block_ptr)session_->net_read_iob->buffer(),
                                   session_->net_read_iob->buffer_size());
            if (PUMP_LIKELY(size > 0)) {
                session_->net_read_data_size = size;
                session_->net_read_data_pos = 0;
                return FLOW_ERR_NO;
            } else if (PUMP_UNLIKELY(size < 0)) {
                return FLOW_ERR_AGAIN;
            }

            PUMP_WARN_LOG("flow_tls::read_from_net: failed");
            return FLOW_ERR_ABORT;
        }
#endif

        int32 flow_tls::read_from_ssl(block_ptr b, int32 size) {
            int32 ret = (int32)ssl::tls_read(session_, b, size);
            if (ret > 0) {
                return ret;
            } else if (ret < 0) {
                return -1;
            }

            PUMP_WARN_LOG("flow_tls::read_from_net: failed %d", ret);

            return 0;
        }

        flow_error flow_tls::send_to_ssl(toolkit::io_buffer_ptr iob) {
            PUMP_ASSERT(iob && iob->data_size() > 0);
            do {
                int32 size = ssl::tls_send(session_, iob->data(), iob->data_size());
                if (size <= 0 || !iob->shift(size))
                    break;
                if (iob->data_size() == 0)
                    return FLOW_ERR_NO;
            } while (true);

            return FLOW_ERR_ABORT;
        }

        flow_error flow_tls::want_to_send() {
#if defined(PUMP_HAVE_IOCP)
            net::update_iocp_task_buffer(send_task_);
            if (net::post_iocp_send(send_task_)) {
                return FLOW_ERR_NO;
            }
#else
            int32 size = net::send(fd_,
                                   session_->net_send_iob->buffer(),
                                   session_->net_send_iob->data_size());
            if (PUMP_LIKELY(size > 0)) {
                // Shift send buffer
                PUMP_DEBUG_CHECK(session_->net_send_iob->shift(size));

                // There is data to send, then try again
                if (session_->net_send_iob->data_size() > 0)
                    return FLOW_ERR_AGAIN;

                // Send finish, reset send buffer
                session_->net_send_iob->reset();

                return FLOW_ERR_NO;
            } else if (PUMP_UNLIKELY(size < 0)) {
                // Send again
                return FLOW_ERR_AGAIN;
            }
#endif
            PUMP_WARN_LOG("flow_tls::want_to_send: failed");
            return FLOW_ERR_ABORT;
        }

#if defined(PUMP_HAVE_IOCP)
        flow_error flow_tls::send_to_net(void_ptr iocp_task) {
            // net send buffer must has data when using iocp
            PUMP_ASSERT(session_->net_send_iob->data_size() > 0);

            int32 size = net::get_iocp_task_processed_size(iocp_task);
            if (PUMP_LIKELY(size > 0)) {
                // Shift send buffer
                PUMP_DEBUG_CHECK(session_->net_send_iob->shift(size));

                // There is data to send, then send again
                uint32 data_size = session_->net_send_iob->data_size();
                if (data_size > 0) {
                    net::update_iocp_task_buffer(send_task_);
                    if (!net::post_iocp_send(send_task_)) {
                        PUMP_WARN_LOG(
                            "flow_tls::send_to_net: set_iocp_task_buffer failed");
                        return FLOW_ERR_ABORT;
                    }
                    return FLOW_ERR_AGAIN;
                }

                // Send finish, reset send buffer
                session_->net_send_iob->reset();

                return FLOW_ERR_NO;
            }

            PUMP_WARN_LOG("flow_tls::send_to_net: failed");
            return FLOW_ERR_ABORT;
        }
#else
        flow_error flow_tls::send_to_net() {
            uint32 data_size = session_->net_send_iob->data_size();
            if (data_size == 0) {
                return FLOW_ERR_NO;
            }

            int32 size = net::send(fd_, session_->net_send_iob->data(), data_size);
            if (PUMP_LIKELY(size > 0)) {
                // Shift send buffer
                PUMP_DEBUG_CHECK(session_->net_send_iob->shift(size));

                // There is data to send, then send again
                if (session_->net_send_iob->data_size() > 0)
                    return FLOW_ERR_AGAIN;

                // Send finish, reset send buffer
                session_->net_send_iob->reset();

                return FLOW_ERR_NO;
            } else if (PUMP_UNLIKELY(size < 0)) {
                // Send again
                return FLOW_ERR_AGAIN;
            }

            PUMP_WARN_LOG("flow_tls::send_to_net: failed");
            return FLOW_ERR_ABORT;
        }
#endif

    }  // namespace flow
}  // namespace transport
}  // namespace pump
