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

#include "pump/debug.h"
#include "pump/transport/address.h"

namespace pump {
namespace transport {

address::address() noexcept
  : is_v6_(false),
    addrlen_(sizeof(struct sockaddr_in)) {
    memset(&addr_, 0, sizeof(addr_));
}

address::address(const std::string &ip, uint16_t port)
  : is_v6_(false),
    addrlen_(sizeof(struct sockaddr_in)) {
    if (net::string_to_address(
            ip,
            port,
            (struct sockaddr *)addr_,
            &addrlen_)) {
        if (addrlen_ == sizeof(struct sockaddr_in6)) {
            is_v6_ = true;
        }
    }
}

address::address(const struct sockaddr *addr, int32_t addr_len)
  : is_v6_(addr_len == sizeof(struct sockaddr_in6)),
    addrlen_(addr_len) {
    memcpy(&addr_, addr, addr_len);
}

bool address::set(const std::string &ip, uint16_t port) {
    if (!net::string_to_address(
            ip,
            port,
            (struct sockaddr *)addr_,
            &addrlen_)) {
        return false;
    }

    if (addrlen_ == sizeof(struct sockaddr_in6)) {
        is_v6_ = true;
    } else {
        is_v6_ = false;
    }

    return true;
}

bool address::set(const struct sockaddr *addr, int32_t addrlen) {
    if (addrlen == sizeof(struct sockaddr_in6)) {
        is_v6_ = true;
    } else if (addrlen == sizeof(struct sockaddr_in)) {
        is_v6_ = false;
    } else {
        return false;
    }

    addrlen_ = addrlen;
    memcpy(addr_, addr, addrlen);

    return true;
}

std::string address::ip() const {
    char host[128] = {0};
    if (is_v6_) {
        auto v6 = (struct sockaddr_in6 *)addr_;
        if (!inet_ntop(
                AF_INET6,
                &(v6->sin6_addr),
                host,
                sizeof(host) - 1)) {
            return std::string();
        }
    } else {
        auto v4 = (struct sockaddr_in *)addr_;
        if (!inet_ntop(
                AF_INET,
                &(v4->sin_addr),
                host,
                sizeof(host) - 1)) {
            return std::string();
        }
    }

    return std::string(host);
}

uint16_t address::port() const {
    uint16_t port = 0;
    if (is_v6_) {
        auto v6 = (struct sockaddr_in6 *)addr_;
        port = ntohs(v6->sin6_port);
    } else {
        auto v4 = (struct sockaddr_in *)addr_;
        port = ntohs(v4->sin_port);
    }

    return port;
}

std::string address::to_string() const {
    uint16_t port = 0;
    char host[128] = {0};
    if (is_v6_) {
        auto v6 = (struct sockaddr_in6 *)addr_;
        if (!inet_ntop(
                AF_INET6,
                &(v6->sin6_addr),
                host,
                sizeof(host) - 1)) {
            return std::string();
        }
        port = ntohs(v6->sin6_port);
    } else {
        auto v4 = (struct sockaddr_in *)addr_;
        if (!inet_ntop(
                AF_INET,
                &(v4->sin_addr),
                host,
                sizeof(host) - 1)) {
            return std::string();
        }
        port = ntohs(v4->sin_port);
    }

    char tmp[256] = {0};
    pump_snprintf(tmp, sizeof(tmp) - 1, "%s:%d", host, port);
    return std::string(tmp);
}

bool address::operator==(const address &other) const noexcept {
    if (is_v6_ == other.is_v6_ && addrlen_ == other.addrlen_ &&
        memcmp(addr_, other.addr_, addrlen_) == 0) {
        return true;
    }
    return false;
}

bool address::operator<(const address &other) const noexcept {
    if (addrlen_ < other.addrlen_) {
        return true;
    } else if (addrlen_ > other.addrlen_) {
        return false;
    }
    return memcmp(addr_, other.addr_, addrlen_) < 0;
}

}  // namespace transport
}  // namespace pump
