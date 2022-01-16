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
        if (!ch) {
            PUMP_WARN_LOG("channel is invalid");
            return ERROR_FAULT;
        }

        int32_t domain = bind_address.is_ipv6() ? AF_INET6 : AF_INET;
        if ((fd_ = net::create_socket(domain, SOCK_DGRAM)) == INVALID_SOCKET) {
            PUMP_DEBUG_LOG("create socket failed with ec %d", net::last_errno());
            return ERROR_FAULT;
        }
        if (!net::set_reuse(fd_, 1)) {
            PUMP_DEBUG_LOG("set socket address reuse failed with ec %d", net::last_errno());
            return ERROR_FAULT;
        }
        if (!net::set_noblock(fd_, 1)) {
            PUMP_DEBUG_LOG("set socket noblock failed with ec %d", net::last_errno());
            return ERROR_FAULT;
        }
        if (!net::bind(fd_, (sockaddr*)bind_address.get(), bind_address.len())) {
            PUMP_DEBUG_LOG("bind socket address failed with ec %d", net::last_errno());
            return ERROR_FAULT;
        }
        if (!net::set_udp_conn_reset(fd_, false)) {
            PUMP_DEBUG_LOG("set conn reset failed with ec %d", net::last_errno());
            return ERROR_FAULT;
        }

        ch_ = ch;

        return ERROR_OK;
    }

    int32_t flow_udp::send(
        const block_t *b, 
        int32_t size, 
        const address &to_address) {
        return net::send_to(
                fd_, 
                b, 
                size, 
                (struct sockaddr*)to_address.get(), 
                to_address.len());
    }

}  // namespace flow
}  // namespace transport
}  // namespace pump