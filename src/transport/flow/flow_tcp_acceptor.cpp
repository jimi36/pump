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

#include "pump/transport/flow/flow_tcp_acceptor.h"

namespace pump {
namespace transport {
    namespace flow {

        flow_tcp_acceptor::flow_tcp_acceptor() noexcept : is_ipv6_(false) {
#if defined(PUMP_HAVE_IOCP)
            accept_task_ = nullptr;
#endif
        }

        flow_tcp_acceptor::~flow_tcp_acceptor() {
            close();

#if defined(PUMP_HAVE_IOCP)
            if (accept_task_)
                net::unlink_iocp_task(accept_task_);
#endif
        }

        flow_error flow_tcp_acceptor::init(poll::channel_sptr &&ch,
                                           const address &listen_address) {
            PUMP_DEBUG_ASSIGN(ch, ch_, ch);

            is_ipv6_ = listen_address.is_ipv6();
            int32 domain = is_ipv6_ ? AF_INET6 : AF_INET;

#if defined(PUMP_HAVE_IOCP)
            fd_ = net::create_iocp_socket(domain, SOCK_STREAM, net::get_iocp_handler());
            if (fd_ == -1)
                return FLOW_ERR_ABORT;

            extra_fns_ = net::new_iocp_extra_function(fd_);
            if (!extra_fns_)
                return FLOW_ERR_ABORT;

            tmp_cache_.resize(ADDRESS_MAX_LEN * 3);

            auto accept_task = net::new_iocp_task();
            net::set_iocp_task_fd(accept_task, fd_);
            net::set_iocp_task_notifier(accept_task, ch_);
            net::set_iocp_task_type(accept_task, IOCP_TASK_ACCEPT);
            net::set_iocp_task_buffer(
                accept_task, (block_ptr)tmp_cache_.data(), (uint32)tmp_cache_.size());
            accept_task_ = accept_task;
#else
            fd_ = net::create_socket(domain, SOCK_STREAM);
            if (fd_ == -1)
                return FLOW_ERR_ABORT;
#endif
            if (!net::set_reuse(fd_, 1))
                return FLOW_ERR_ABORT;
            if (!net::set_noblock(fd_, 1))
                return FLOW_ERR_ABORT;
            if (!net::set_nodelay(fd_, 1))
                return FLOW_ERR_ABORT;
            if (!net::bind(fd_, (sockaddr *)listen_address.get(), listen_address.len()))
                return FLOW_ERR_ABORT;
            if (!net::listen(fd_))
                return FLOW_ERR_ABORT;

            return FLOW_ERR_NO;
        }

#if defined(PUMP_HAVE_IOCP)
        flow_error flow_tcp_acceptor::want_to_accept() {
            int32 domain = is_ipv6_ ? AF_INET6 : AF_INET;
            int32 client =
                net::create_iocp_socket(domain, SOCK_STREAM, net::get_iocp_handler());
            if (client == -1)
                return FLOW_ERR_ABORT;

            net::set_iocp_task_client_fd(accept_task_, client);
            if (!net::post_iocp_accept(extra_fns_, accept_task_)) {
                net::close(client);
                return FLOW_ERR_ABORT;
            }

            return FLOW_ERR_NO;
        }
#endif

#if defined(PUMP_HAVE_IOCP)
        int32 flow_tcp_acceptor::accept(void_ptr iocp_task,
                                        address_ptr local_address,
                                        address_ptr remote_address) {
            int32 ec = net::get_iocp_task_ec(iocp_task);
            int32 client_fd = net::get_iocp_task_client_fd(iocp_task);
            if (ec != 0 || client_fd == -1) {
                net::close(client_fd);
                return -1;
            }

            sockaddr *local = nullptr;
            sockaddr *remote = nullptr;
            int32 llen = sizeof(sockaddr_in);
            int32 rlen = sizeof(sockaddr_in);
            if (!net::get_iocp_accepted_address(
                    extra_fns_, iocp_task, &local, &llen, &remote, &rlen)) {
                net::close(client_fd);
                return -1;
            }
            local_address->set(local, llen);
            remote_address->set(remote, rlen);

            net::set_iocp_task_client_fd(iocp_task, 0);
            if (!net::set_noblock(client_fd, 1) || !net::set_nodelay(client_fd, 1)) {
                net::close(client_fd);
                return -1;
            }

            return client_fd;
        }
#else
        int32 flow_tcp_acceptor::accept(address_ptr local_address,
                                        address_ptr remote_address) {
            int32 addrlen = ADDRESS_MAX_LEN;
            int32 client_fd =
                net::accept(fd_, (struct sockaddr *)tmp_cache_.data(), &addrlen);
            if (client_fd == -1)
                return -1;
            remote_address->set((sockaddr *)tmp_cache_.data(), addrlen);

            addrlen = ADDRESS_MAX_LEN;
            net::local_address(client_fd, (sockaddr *)tmp_cache_.data(), &addrlen);
            local_address->set((sockaddr *)tmp_cache_.data(), addrlen);

            if (!net::set_noblock(client_fd, 1) || !net::set_nodelay(client_fd, 1)) {
                net::close(client_fd);
                return -1;
            }

            return client_fd;
        }
#endif

    }  // namespace flow
}  // namespace transport
}  // namespace pump
