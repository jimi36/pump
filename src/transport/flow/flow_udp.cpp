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

        const static uint32_t UDP_BUFFER_SIZE = 1024 * 64;

        flow_udp::flow_udp() noexcept
          : read_iob_(nullptr) {
#if defined(PUMP_HAVE_IOCP)
            read_task_ = nullptr;
#endif
        }

        flow_udp::~flow_udp() {
#if defined(PUMP_HAVE_IOCP)
            if (read_task_) {
                read_task_->sub_link();
            }
#endif
        }

        flow_error flow_udp::init(poll::channel_sptr &&ch, const address &bind_address) {
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
                PUMP_ERR_LOG("flow_udp::init: create socket failed");
                return FLOW_ERR_ABORT;
            }

            read_iob_ = toolkit::io_buffer::create();
            read_iob_->init_with_size(UDP_BUFFER_SIZE);

#if defined(PUMP_HAVE_IOCP)
            read_task_ = net::new_iocp_task();
            read_task_->set_fd(fd_);
            read_task_->set_notifier(ch_);
            read_task_->set_type(net::IOCP_TASK_READ);
            read_task_->bind_io_buffer(read_iob_);
#endif
            if (!net::set_reuse(fd_, 1)) {
                PUMP_ERR_LOG("flow_udp::init: set reuse failed");
                return FLOW_ERR_ABORT;
            }
            if (!net::set_noblock(fd_, 1)) {
                PUMP_ERR_LOG("flow_udp::init: set noblock failed");
                return FLOW_ERR_ABORT;
            }
            if (!net::bind(fd_, (sockaddr*)bind_address.get(), bind_address.len())) {
                PUMP_ERR_LOG("flow_udp::init: bind failed");
                return FLOW_ERR_ABORT;
            }
            if (!net::set_udp_conn_reset(fd_, false)) {
                PUMP_ERR_LOG("flow_udp::init: set udp conn reset failed");
                return FLOW_ERR_ABORT;
            }

            return FLOW_ERR_NO;
        }

#if defined(PUMP_HAVE_IOCP)
        flow_error flow_udp::want_to_read() {
            PUMP_ASSERT(read_task_);
            if (!net::post_iocp_read_from(read_task_)) {
                PUMP_WARN_LOG("flow_udp::want_to_read: post iocp read from failed");
                return FLOW_ERR_ABORT;
            }
            return FLOW_ERR_NO;
        }
#endif

#if defined(PUMP_HAVE_IOCP)
        const block_t* flow_udp::read_from(net::iocp_task_ptr iocp_task,
                                        int32_t *size,
                                        address_ptr from_address) {
            const block_t *buf = iocp_task->get_processed_data(size);
            if (PUMP_LIKELY(*size > 0)) {
                int32_t addrlen = 0;
                sockaddr *addr = iocp_task->get_remote_address(&addrlen);
                from_address->set(addr, addrlen);
            }
            return buf;
        }
#else
        const block_t* flow_udp::read_from(int32_t *size, address_ptr from_address) {
            block_t addr[ADDRESS_MAX_LEN];
            int32_t addrlen = ADDRESS_MAX_LEN;
            block_t *buf = (block_t*)read_iob_->buffer();
            *size = net::read_from(fd_, 
                                   buf, 
                                   read_iob_->buffer_size(), 
                                   (sockaddr*)addr, &addrlen);
            from_address->set((sockaddr*)addr, addrlen);

            return buf;
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