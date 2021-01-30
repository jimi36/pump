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

#include "pump/transport/flow/flow_udp.h"

namespace pump {
namespace transport {
    namespace flow {

        flow_udp::flow_udp() noexcept {
        }

        flow_udp::~flow_udp() {
        }

        int32_t flow_udp::init(poll::channel_sptr &&ch, const address &bind_address) {
            PUMP_DEBUG_ASSIGN(ch, ch_, ch);

            int32_t domain = AF_INET;
            if (bind_address.is_ipv6()) {
                domain = AF_INET6;
            }

#if defined(PUMP_HAVE_IOCP)
            fd_ = net::create_iocp_socket(domain, SOCK_DGRAM, net::get_iocp_handler());
#else
            fd_ = net::create_socket(domain, SOCK_DGRAM);
#endif
            if (fd_ == -1) {
                PUMP_DEBUG_LOG("flow_udp: init failed for creating socket failed");
                return FLOW_ERR_ABORT;
            }

            if (!net::set_reuse(fd_, 1)) {
                PUMP_DEBUG_LOG("flow_udp: init failed for setting socket reuse failed");
                return FLOW_ERR_ABORT;
            }
            if (!net::set_noblock(fd_, 1)) {
                PUMP_DEBUG_LOG("flow_udp: init failed for setting socket noblock failed");
                return FLOW_ERR_ABORT;
            }
            if (!net::bind(fd_, (sockaddr*)bind_address.get(), bind_address.len())) {
                PUMP_DEBUG_LOG("flow_udp: init failed for socket bind address failed");
                return FLOW_ERR_ABORT;
            }
            if (!net::set_udp_conn_reset(fd_, false)) {
                PUMP_DEBUG_LOG("flow_udp: init failed for setting socket conn reset failed");
                return FLOW_ERR_ABORT;
            }

            return FLOW_ERR_NO;
        }

#if defined(PUMP_HAVE_IOCP)
        int32_t flow_udp::post_read(net::iocp_task_ptr iocp_task) {
            if (!iocp_task) {
                auto iob = toolkit::io_buffer::create();
                iob->init_with_size(MAX_UDP_BUFFER_SIZE);
                iocp_task = net::new_iocp_task();
                iocp_task->set_fd(fd_);
                iocp_task->set_notifier(ch_);
                iocp_task->set_kind(net::IOCP_TASK_READ);
                iocp_task->bind_io_buffer(iob);
            } else {
                iocp_task->add_link();
            }
            if (!net::post_iocp_read_from(iocp_task)) {
                PUMP_DEBUG_LOG("flow_udp: post read task failed");
                return FLOW_ERR_ABORT;
            }
            return FLOW_ERR_NO;
        }
#endif

        int32_t flow_udp::send(const block_t *b, int32_t size, const address &to_address) {
            return net::send_to(fd_, 
                                b, 
                                size, 
                                (struct sockaddr*)to_address.get(), 
                                to_address.len());
        }

    }  // namespace flow
}  // namespace transport
}  // namespace pump