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

flow_udp::flow_udp() pump_noexcept {
}

bool flow_udp::init(
    poll::channel_sptr &&ch,
    const address &bind_address) {
    if (!ch) {
        pump_debug_log("channel invalid");
        return false;
    }

    int32_t domain = bind_address.is_ipv6() ? AF_INET6 : AF_INET;
    if ((fd_ = net::create_socket(domain, SOCK_DGRAM)) == invalid_socket) {
        pump_debug_log("create socket failed %d", net::last_errno());
        return false;
    }
    if (!net::set_reuse(fd_, 1)) {
        pump_debug_log("set socket address reuse ec %d", net::last_errno());
        return false;
    }
    if (!net::set_noblock(fd_, 1)) {
        pump_debug_log("set socket noblock failed %d", net::last_errno());
        return false;
    }
    if (!net::bind(fd_, (sockaddr *)bind_address.get(), bind_address.len())) {
        pump_debug_log("bind socket address failed %d", net::last_errno());
        return false;
    }
    if (!net::set_udp_conn_reset(fd_, false)) {
        pump_debug_log("set conn reset failed %d", net::last_errno());
        return false;
    }

    ch_ = ch;

    return true;
}

int32_t flow_udp::read_from(
    char *b,
    int32_t size,
    address *from) {
    int32_t addrlen = max_address_len;
    struct sockaddr *addr = from->get();
    size = net::read_from(fd_, b, size, addr, &addrlen);
    if (size > 0) {
        from->set((sockaddr *)addr, addrlen);
    }
    return size;
}

int32_t flow_udp::send(
    const char *b,
    int32_t size,
    const address &to) {
    return net::send_to(
        fd_,
        b,
        size,
        (struct sockaddr *)to.get(),
        to.len());
}

}  // namespace flow
}  // namespace transport
}  // namespace pump