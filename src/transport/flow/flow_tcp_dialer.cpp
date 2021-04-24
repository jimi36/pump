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

    flow_tcp_dialer::flow_tcp_dialer() noexcept
      : is_ipv6_(false) {
    }

    flow_tcp_dialer::~flow_tcp_dialer() {
    }

    int32_t flow_tcp_dialer::init(
        poll::channel_sptr &&ch, 
        const address &bind_address) {
        PUMP_DEBUG_FAILED(
            !ch, 
            "flow_tcp_dialer: init failed for channel invalid",
            return FLOW_ERR_ABORT);
        ch_ = ch;

        is_ipv6_ = bind_address.is_ipv6();
        int32_t domain = is_ipv6_ ? AF_INET6 : AF_INET;

        if ((fd_ = net::create_socket(domain, SOCK_STREAM)) == INVALID_SOCKET) {
            PUMP_DEBUG_LOG("flow_tcp_dialer: init failed for creating socket failed");
            return FLOW_ERR_ABORT;
        }

        if (!net::set_reuse(fd_, 1)) {
            PUMP_DEBUG_LOG("flow_tcp_dialer: init failed for setting socket reuse failed");
            return FLOW_ERR_ABORT;
        }
        if (!net::set_noblock(fd_, 1)) {
            PUMP_DEBUG_LOG("flow_tcp_dialer: init failed for setting socket noblock failed");
            return FLOW_ERR_ABORT;
        }
        if (!net::set_nodelay(fd_, 1)) {
            PUMP_DEBUG_LOG("flow_tcp_dialer: init failed for setting socket nodelay failed");
            return FLOW_ERR_ABORT;
        }
        if (!net::bind(fd_, (sockaddr*)bind_address.get(), bind_address.len())) {
            PUMP_DEBUG_LOG("flow_tcp_dialer: init failed for binding socket address failed");
            return FLOW_ERR_ABORT;
        }

        return FLOW_ERR_NO;
    }

    int32_t flow_tcp_dialer::post_connect(const address &remote_address) {
        if (!net::connect(fd_, (sockaddr*)remote_address.get(), remote_address.len())) {
            PUMP_DEBUG_LOG(
                "flow_tcp_dialer: post connect failed for %d", 
                net::last_errno());
            return FLOW_ERR_ABORT;
        }
        return FLOW_ERR_NO;
    }

    int32_t flow_tcp_dialer::connect(
        address *local_address, 
        address *remote_address) {
        int32_t ec = net::get_socket_error(fd_);
        if (ec != 0) {
            return ec;
        }

        if (!net::update_connect_context(fd_)) {
            PUMP_DEBUG_LOG(
                "flow_tcp_dialer: connect failed for updating connect context failed");
            return net::get_socket_error(fd_);
        }

        int32_t addrlen = 0;
        block_t addr[ADDRESS_MAX_LEN];

        addrlen = ADDRESS_MAX_LEN;
        net::local_address(fd_, (sockaddr*)addr, &addrlen);
        local_address->set((sockaddr*)addr, addrlen);

        addrlen = ADDRESS_MAX_LEN;
        net::remote_address(fd_, (sockaddr*)addr, &addrlen);
        remote_address->set((sockaddr*)addr, addrlen);

        return ec;
    }

}  // namespace flow
}  // namespace transport
}  // namespace pump