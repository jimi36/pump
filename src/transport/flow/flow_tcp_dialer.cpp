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

flow_tcp_dialer::flow_tcp_dialer() noexcept :
    is_ipv6_(false) {}

flow_tcp_dialer::~flow_tcp_dialer() {}

error_code flow_tcp_dialer::init(
    poll::channel_sptr &&ch,
    const address &bind_address) {
    if (!ch) {
        pump_warn_log("channel is invalid");
        return error_fault;
    }

    int32_t domain = bind_address.is_ipv6() ? AF_INET6 : AF_INET;
    if ((fd_ = net::create_socket(domain, SOCK_STREAM)) == invalid_socket) {
        pump_warn_log(
            "create socket failed with ec %d",
            net::last_errno());
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
    if (!net::bind(fd_, (sockaddr *)bind_address.get(), bind_address.len())) {
        pump_warn_log(
            "bind socket address failed with ec %d",
            net::last_errno());
        return error_fault;
    }

    ch_ = ch;

    return error_none;
}

int32_t flow_tcp_dialer::post_connect(const address &remote_address) {
    if (!net::connect(
            fd_,
            (sockaddr *)remote_address.get(),
            remote_address.len())) {
        pump_warn_log("socket connect failed with ec %d", net::last_errno());
        return error_fault;
    }
    return error_none;
}

int32_t flow_tcp_dialer::connect(
    address *local_address,
    address *remote_address) {
    int32_t ec = net::get_socket_error(fd_);
    if (ec != 0) {
        return ec;
    }

    if (!net::update_connect_context(fd_)) {
        pump_warn_log(
            "update socket connect context failed with ec %d",
            net::last_errno());
        return net::get_socket_error(fd_);
    }

    int32_t addrlen = 0;
    char addr[max_address_len];

    addrlen = max_address_len;
    net::local_address(fd_, (sockaddr *)addr, &addrlen);
    local_address->set((sockaddr *)addr, addrlen);

    addrlen = max_address_len;
    net::remote_address(fd_, (sockaddr *)addr, &addrlen);
    remote_address->set((sockaddr *)addr, addrlen);

    return ec;
}

}  // namespace flow
}  // namespace transport
}  // namespace pump