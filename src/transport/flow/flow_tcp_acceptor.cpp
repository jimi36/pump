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

flow_tcp_acceptor::flow_tcp_acceptor() noexcept :
    is_ipv6_(false),
    iob_(nullptr) {}

flow_tcp_acceptor::~flow_tcp_acceptor() {
    if (iob_) {
        iob_->unrefer();
    }
}

error_code flow_tcp_acceptor::init(
    poll::channel_sptr &&ch,
    const address &listen_address) {
    if (!ch) {
        pump_warn_log("channel is invalid");
        return error_fault;
    }

    iob_ = toolkit::io_buffer::create(max_address_len * 3);
    if (iob_ == nullptr) {
        pump_warn_log("new io buffer object failed");
        return error_fault;
    }

    int32_t domain = listen_address.is_ipv6() ? AF_INET6 : AF_INET;
    if ((fd_ = net::create_socket(domain, SOCK_STREAM)) == invalid_socket) {
        pump_warn_log("create socket failed with ec %d", net::last_errno());
        return error_fault;
    }
    if (!net::set_reuse(fd_, 1)) {
        pump_warn_log(
            "set socket address reuse failed with ec %d",
            net::last_errno());
        return error_fault;
    }
    if (!net::set_noblock(fd_, 1)) {
        pump_warn_log(
            "set socket noblock failed with ec %d",
            net::last_errno());
        return error_fault;
    }
    if (!net::set_nodelay(fd_, 1)) {
        pump_warn_log(
            "set socket nodelay failed with ec %d",
            net::last_errno());
        return error_fault;
    }
    if (!net::bind(
            fd_,
            (sockaddr *)listen_address.get(),
            listen_address.len())) {
        pump_warn_log(
            "bind socket address failed with ec %d",
            net::last_errno());
        return error_fault;
    }
    if (!net::listen(fd_)) {
        pump_warn_log("listen failed with ec %d", net::last_errno());
        return error_fault;
    }

    ch_ = ch;

    return error_none;
}

pump_socket flow_tcp_acceptor::accept(
    address *local_address,
    address *remote_address) {
    int32_t addrlen = max_address_len;
    pump_socket client_fd = net::accept(
        fd_,
        (struct sockaddr *)iob_->raw(),
        &addrlen);
    if (client_fd == invalid_socket) {
        pump_warn_log("accept socket failed with ec %d", net::last_errno());
        return invalid_socket;
    }

    remote_address->set((sockaddr *)iob_->raw(), addrlen);

    addrlen = max_address_len;
    net::local_address(client_fd, (sockaddr *)iob_->raw(), &addrlen);
    local_address->set((sockaddr *)iob_->raw(), addrlen);

    if (!net::set_noblock(client_fd, 1) || !net::set_nodelay(client_fd, 1)) {
        pump_warn_log(
            "set socket noblock or nodelay failed with ec %d",
            net::last_errno());
        net::close(client_fd);
        return invalid_socket;
    }

    return client_fd;
}

}  // namespace flow
}  // namespace transport
}  // namespace pump
