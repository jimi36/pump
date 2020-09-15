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

#include "pump/transport/flow/flow_tcp_dialer.h"

namespace pump {
namespace transport {
    namespace flow {

        flow_tcp_dialer::flow_tcp_dialer() noexcept : is_ipv6_(false) {
#if defined(PUMP_HAVE_IOCP)
            dial_task_ = nullptr;
#endif
        }

        flow_tcp_dialer::~flow_tcp_dialer() {
#if defined(PUMP_HAVE_IOCP)
            if (dial_task_)
                net::unlink_iocp_task(dial_task_);
#endif
        }

        flow_error flow_tcp_dialer::init(poll::channel_sptr &&ch,
                                         const address &bind_address) {
            PUMP_DEBUG_ASSIGN(ch, ch_, ch);

            is_ipv6_ = bind_address.is_ipv6();
            int32 domain = is_ipv6_ ? AF_INET6 : AF_INET;

#if defined(PUMP_HAVE_IOCP)
            fd_ = net::create_iocp_socket(domain, SOCK_STREAM, net::get_iocp_handler());
            if (fd_ == -1) {
                PUMP_ERR_LOG("flow::flow_tcp_dialer::init: create_iocp_socket fialed");
                return FLOW_ERR_ABORT;
            }

            extra_fns_ = net::new_iocp_extra_function(fd_);
            if (!extra_fns_) {
                PUMP_ERR_LOG(
                    "flow::flow_tcp_dialer::init: new_iocp_extra_function fialed");
                return FLOW_ERR_ABORT;
            }

            auto dial_task = net::new_iocp_task();
            net::set_iocp_task_fd(dial_task, fd_);
            net::set_iocp_task_notifier(dial_task, ch_);
            net::set_iocp_task_type(dial_task, IOCP_TASK_CONNECT);
            dial_task_ = dial_task;
#else
            if ((fd_ = net::create_socket(domain, SOCK_STREAM)) == -1) {
                PUMP_ERR_LOG("flow::flow_tcp_dialer::init: create_socket fialed");
                return FLOW_ERR_ABORT;
            }
#endif
            if (!net::set_reuse(fd_, 1)) {
                PUMP_ERR_LOG("flow::flow_tcp_dialer::init: set_reuse failed");
                return FLOW_ERR_ABORT;
            }
            if (!net::set_noblock(fd_, 1)) {
                PUMP_ERR_LOG("flow::flow_tcp_dialer::init: set_noblock failed");
                return FLOW_ERR_ABORT;
            }
            if (!net::set_nodelay(fd_, 1)) {
                PUMP_ERR_LOG("flow::flow_tcp_dialer::init: set_nodelay failed");
                return FLOW_ERR_ABORT;
            }
            if (!net::bind(fd_, (sockaddr *)bind_address.get(), bind_address.len())) {
                PUMP_ERR_LOG("flow::flow_tcp_dialer::init: bind failed");
                return FLOW_ERR_ABORT;
            }

            return FLOW_ERR_NO;
        }

        flow_error flow_tcp_dialer::want_to_connect(const address &remote_address) {
#if defined(PUMP_HAVE_IOCP)
            if (!net::post_iocp_connect(
                    extra_fns_, dial_task_, remote_address.get(), remote_address.len())) {
                PUMP_WARN_LOG(
                    "flow::flow_tcp_dialer::want_to_connect: post_iocp_connect failed");
                return FLOW_ERR_ABORT;
            }
#else
            if (!net::connect(
                    fd_, (sockaddr *)remote_address.get(), remote_address.len())) {
                PUMP_WARN_LOG("flow::flow_tcp_dialer::want_to_connect: connect failed");
                return FLOW_ERR_ABORT;
            }
#endif
            return FLOW_ERR_NO;
        }

#if defined(PUMP_HAVE_IOCP)
        int32 flow_tcp_dialer::connect(void_ptr iocp_task,
                                       address_ptr local_address,
                                       address_ptr remote_address) {
            PUMP_ASSERT(iocp_task);
            int32 ec = net::get_iocp_task_ec(iocp_task);
            if (ec != 0)
                return ec;

            if (!net::update_connect_context(fd_)) {
                PUMP_WARN_LOG(
                    "flow::flow_tcp_dialer::connect: update_connect_context failed");
                return net::get_socket_error(fd_);
            }

            int32 addrlen = 0;
            block addr[ADDRESS_MAX_LEN];

            addrlen = ADDRESS_MAX_LEN;
            net::local_address(fd_, (sockaddr *)addr, &addrlen);
            local_address->set((sockaddr *)addr, addrlen);

            addrlen = ADDRESS_MAX_LEN;
            net::remote_address(fd_, (sockaddr *)addr, &addrlen);
            remote_address->set((sockaddr *)addr, addrlen);

            return ec;
        }
#else
        int32 flow_tcp_dialer::connect(address_ptr local_address,
                                       address_ptr remote_address) {
            int32 ec = net::get_socket_error(fd_);
            if (ec != 0)
                return ec;

            if (!net::update_connect_context(fd_)) {
                PUMP_WARN_LOG(
                    "flow::flow_tcp_dialer::connect: update_connect_context failed");
                return net::get_socket_error(fd_);
            }

            int32 addrlen = 0;
            block addr[ADDRESS_MAX_LEN];

            addrlen = ADDRESS_MAX_LEN;
            net::local_address(fd_, (sockaddr *)addr, &addrlen);
            local_address->set((sockaddr *)addr, addrlen);

            addrlen = ADDRESS_MAX_LEN;
            net::remote_address(fd_, (sockaddr *)addr, &addrlen);
            remote_address->set((sockaddr *)addr, addrlen);

            return ec;
        }
#endif

    }  // namespace flow
}  // namespace transport
}  // namespace pump