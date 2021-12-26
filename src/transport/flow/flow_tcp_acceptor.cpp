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

    flow_tcp_acceptor::flow_tcp_acceptor() noexcept
        : is_ipv6_(false), 
        iob_(nullptr) {
    }

    flow_tcp_acceptor::~flow_tcp_acceptor() {
        if (iob_) {
            iob_->sub_refence();
        }
    }

    error_code flow_tcp_acceptor::init(
        poll::channel_sptr &&ch, 
        const address &listen_address) {
        PUMP_DEBUG_FAILED(
            !ch, 
            "flow_tcp_acceptor: init failed for channel invalid",
            return ERROR_FAULT);
        ch_ = ch;

        is_ipv6_ = listen_address.is_ipv6();
        int32_t domain = is_ipv6_ ? AF_INET6 : AF_INET;

        iob_ = toolkit::io_buffer::create();
        iob_->init(ADDRESS_MAX_LEN * 3);

        fd_ = net::create_socket(domain, SOCK_STREAM);
        if (fd_ == INVALID_SOCKET) {
            PUMP_DEBUG_LOG("flow_tcp_acceptor: init failed for creating socket failed");
            return ERROR_FAULT;
        }

        if (!net::set_reuse(fd_, 1)) {
            PUMP_DEBUG_LOG("flow_tcp_acceptor: init failed for setting socket reuse failed");
            return ERROR_FAULT;
        }
        if (!net::set_noblock(fd_, 1)) {
            PUMP_DEBUG_LOG("flow_tcp_acceptor: init failed for setting socket noblock failed");
            return ERROR_FAULT;
        }
        if (!net::set_nodelay(fd_, 1)) {
            PUMP_DEBUG_LOG("flow_tcp_acceptor: init failed for setting socket nodelay failed");
            return ERROR_FAULT;
        }
        if (!net::bind(fd_, (sockaddr*)listen_address.get(), listen_address.len())) {
            PUMP_DEBUG_LOG("flow_tcp_acceptor: init failed for binding socket address failed");
            return ERROR_FAULT;
        }
        if (!net::listen(fd_)) {
            PUMP_DEBUG_LOG("flow_tcp_acceptor: init failed for listening failed");
            return ERROR_FAULT;
        }

        return ERROR_OK;
    }

    pump_socket flow_tcp_acceptor::accept(
        address *local_address, 
        address *remote_address) {
        int32_t addrlen = ADDRESS_MAX_LEN;
        pump_socket client_fd = net::accept(fd_, (struct sockaddr*)iob_->raw(), &addrlen);
        if (client_fd == INVALID_SOCKET) {
            PUMP_DEBUG_LOG(
                "flow_tcp_acceptor: accept failed for %d", 
                net::last_errno());
            return -1;
        }
            
        remote_address->set((sockaddr*)iob_->raw(), addrlen);

        addrlen = ADDRESS_MAX_LEN;
        net::local_address(client_fd, (sockaddr*)iob_->raw(), &addrlen);
        local_address->set((sockaddr*)iob_->raw(), addrlen);

        if (!net::set_noblock(client_fd, 1) || 
            !net::set_nodelay(client_fd, 1)) {
            PUMP_DEBUG_LOG(
                "flow_tcp_acceptor: accept failed for setting noblock or nodelay failed");
            net::close(client_fd);
            return -1;
        }

        return client_fd;
    }

}  // namespace flow
}  // namespace transport
}  // namespace pump
