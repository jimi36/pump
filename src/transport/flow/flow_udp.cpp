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

        const static uint32 UDP_BUFFER_SIZE = 1024 * 64;

        flow_udp::flow_udp() noexcept : read_iob_(nullptr) {
#if defined(PUMP_HAVE_IOCP)
            read_task_ = nullptr;
#endif
        }

        flow_udp::~flow_udp() {
#if defined(PUMP_HAVE_IOCP)
            if (read_task_) {
                net::unlink_iocp_task(read_task_);
            }
#endif
        }

        flow_error flow_udp::init(poll::channel_sptr &&ch, const address &bind_address) {
            PUMP_DEBUG_ASSIGN(ch, ch_, ch);

            int32 domain = AF_INET;
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
            auto read_task = net::new_iocp_task();
            net::set_iocp_task_fd(read_task, fd_);
            net::set_iocp_task_notifier(read_task, ch_);
            net::set_iocp_task_type(read_task, IOCP_TASK_READ);
            net::bind_iocp_task_buffer(read_task, read_iob_);
            read_task_ = read_task;
#endif
            if (!net::set_reuse(fd_, 1)) {
                PUMP_ERR_LOG("flow_udp::init: set reuse failed");
                return FLOW_ERR_ABORT;
            }
            if (!net::set_noblock(fd_, 1)) {
                PUMP_ERR_LOG("flow_udp::init: set noblock failed");
                return FLOW_ERR_ABORT;
            }
            if (!net::bind(fd_, (sockaddr *)bind_address.get(), bind_address.len())) {
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
        c_block_ptr flow_udp::read_from(void_ptr iocp_task,
                                        int32_ptr size,
                                        address_ptr from_address) {
            c_block_ptr buf = net::get_iocp_task_processed_data(iocp_task, size);
            if (PUMP_LIKELY(*size > 0)) {
                int32 addrlen = 0;
                sockaddr *addr = net::get_iocp_task_remote_address(iocp_task, &addrlen);
                from_address->set(addr, addrlen);
            }
            return buf;
        }
#else
        c_block_ptr flow_udp::read_from(int32_ptr size, address_ptr from_address) {
            block addr[ADDRESS_MAX_LEN];
            int32 addrlen = ADDRESS_MAX_LEN;
            block_ptr buf = (block_ptr)read_iob_->buffer();
            *size = net::read_from(fd_, 
                                   buf, 
                                   read_iob_->buffer_size(), 
                                   (sockaddr *)addr, &addrlen);
            from_address->set((sockaddr *)addr, addrlen);

            return buf;
        }
#endif

        int32 flow_udp::send(c_block_ptr b, uint32 size, const address &to_address) {
            return net::send_to(fd_, 
                                b, 
                                size,
                                (struct sockaddr *)to_address.get(),
                                to_address.len());
        }

    }  // namespace flow
}  // namespace transport
}  // namespace pump