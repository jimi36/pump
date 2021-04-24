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
#include "pump/net/error.h"
#include "pump/net/socket.h"

namespace pump {
namespace net {

    pump_socket create_socket(
        int32_t domain, 
        int32_t type) {
        return (pump_socket)::socket(domain, type, 0);
    }

    bool set_noblock(
        pump_socket fd, 
        int32_t noblock) {
#if defined(PUMP_HAVE_WINSOCK)
#if defined(OS_CYGWIN)
        long cmd = 0x8004667e;
        __ms_u_long mode = (noblock == 0) ? 0 : 1;  // non-blocking mode
#else
        long cmd = FIONBIO;
        u_long mode = (noblock == 0) ? 0 : 1;  // non-blocking mode
#endif
        if (ioctlsocket(fd, cmd, &mode) != SOCKET_ERROR) {
            return true;
        }
#else
        int32_t flags = fcntl(fd, F_GETFL, 0);
        flags = (noblock == 0) ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
        if (fcntl(fd, F_SETFL, flags) != -1) {
            return true;
        }
#endif
        PUMP_DEBUG_LOG("net: set_noblock failed %d", last_errno());
        PUMP_ASSERT(false);
        return false;
    }

    bool set_linger(
        pump_socket fd, 
        uint16_t on, 
        uint16_t linger) {
        struct linger lgr;
        lgr.l_onoff = on;
        lgr.l_linger = linger;
        if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (const block_t*)&lgr, sizeof(lgr)) == 0) {
            return true;
        }
        PUMP_DEBUG_LOG("net: set_linger failed %d", last_errno());
        PUMP_ASSERT(false);
        return false;
    }

    bool set_read_bs(
        pump_socket fd,
        int32_t size) {
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const block_t*)&size, sizeof(size)) == 0) {
            return true;
        }
        PUMP_DEBUG_LOG("net: set_read_bs failed %d", last_errno());
        PUMP_ASSERT(false);
        return false;
    }

    bool set_send_bs(
        pump_socket fd, 
        int32_t size) {
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const block_t*)&size, sizeof(size)) == 0) {
            return true;
        }
        PUMP_DEBUG_LOG("net: set_send_bs failed %d", last_errno());
        PUMP_ASSERT(false);
        return false;
    }

    bool set_keeplive(
        pump_socket fd, 
        int32_t keeplive, 
        int32_t interval) {
        int32_t on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const block_t*)&on, sizeof(on)) == -1) {
            PUMP_DEBUG_LOG("net: set_keeplive failed %d", last_errno());
            PUMP_ASSERT(false);
            return false;
        }

#if defined(PUMP_HAVE_WINSOCK)
        DWORD bytes = 0;
        struct tcp_keepalive keepalive;
        keepalive.onoff = 1;
        keepalive.keepalivetime = keeplive * 1000;
        keepalive.keepaliveinterval = interval * 1000;
        if (WSAIoctl(
                fd,
                SIO_KEEPALIVE_VALS,
                &keepalive,
                sizeof(keepalive),
                nullptr,
                0,
                &bytes,
                nullptr,
                nullptr) == -1) {
            PUMP_DEBUG_LOG("net: set_keeplive failed %d", last_errno());
            PUMP_ASSERT(false);
            return false;
        }
#else
        int32_t count = 3;
        if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &keeplive, sizeof(keeplive)) == -1 ||
            setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)) == -1 ||
            setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &count, sizeof(count)) == -1) {
            PUMP_DEBUG_LOG("net: set_keeplive failed %d", last_errno());
            PUMP_ASSERT(false);
            return false;
        }
#endif
        return true;
    }

    bool set_reuse(
        pump_socket fd, 
        int32_t reuse) {
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const block_t*)&reuse, sizeof(reuse)) == 0) {
            return true;
        }
        PUMP_DEBUG_LOG("net: set_reuse failed %d", last_errno());
        PUMP_ASSERT(false);
        return false;
    }

    bool set_nodelay(
        pump_socket fd, 
        int32_t nodelay) {
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const block_t*)&nodelay, sizeof(nodelay)) == 0) {
            return true;
        }
        PUMP_DEBUG_LOG("net: set_nodelay failed %d", last_errno());
        PUMP_ASSERT(false);
        return false;
    }

    bool update_connect_context(pump_socket fd) {
#if defined(PUMP_HAVE_WINSOCK)
        if (setsockopt(fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr, 0) == 0) {
            return true;
        }
        PUMP_DEBUG_LOG("net: update_connect_context failed %d", last_errno());
        PUMP_ASSERT(false);
        return false;
#else
        return true;
#endif
    }

    bool set_udp_conn_reset(
        pump_socket fd, 
        bool enable) {
#if defined(PUMP_HAVE_WINSOCK)
        DWORD bytes_returned = 0;
        BOOL behavior = enable ? TRUE : FALSE;
        if (WSAIoctl(
                fd,
                SIO_UDP_CONNRESET,
                &behavior,
                sizeof(behavior),
                nullptr,
                0,
                &bytes_returned,
                nullptr,
                nullptr) == SOCKET_ERROR &&
            last_errno() != WSAEWOULDBLOCK) {
            PUMP_DEBUG_LOG("net: set_udp_conn_reset failed %d", last_errno());
            PUMP_ASSERT(false);
            return false;
        }
#endif
        return true;
    }

    bool bind(
        pump_socket fd, 
        struct sockaddr *addr, 
        int32_t addrlen) {
        if (::bind(fd, addr, addrlen) == 0) {
            return true;
        }
        PUMP_DEBUG_LOG("net: bind failed %d", last_errno());
        return false;
    }

    bool listen(
        pump_socket fd, 
        int32_t backlog) {
        if (::listen(fd, backlog) == 0) {
            return true;
        }
        PUMP_DEBUG_LOG("net: listen failed %d", last_errno());
        return false;
    }

    pump_socket accept(
        pump_socket fd, 
        struct sockaddr *addr, 
        int32_t *addrlen) {
        pump_socket client = ::accept(fd, addr, (socklen_t*)addrlen);
        if (client < 0) {
            PUMP_DEBUG_LOG("net: accept failed %d", last_errno());
        }
        return client;
    }

    bool connect(
        pump_socket fd, 
        struct sockaddr *addr, 
        int32_t addrlen) {
        if (::connect(fd, addr, addrlen) != 0) {
            int32_t ec = net::last_errno();
            if (ec != LANE_EALREADY && 
                ec != LANE_EWOULDBLOCK && 
                ec != LANE_EINPROGRESS) {
                PUMP_DEBUG_LOG("net: connect failed %d", ec);
                return false;
            }
        }
        return true;
    }

    int32_t read(
        pump_socket fd, 
        block_t *b, 
        int32_t size) {
        size = ::recv(fd, b, size, 0);
        if (PUMP_LIKELY(size > 0)) {
            return size;
        } else if (size < 0) {
           int32_t ec = net::last_errno();
            if (ec == LANE_EINPROGRESS || ec == LANE_EWOULDBLOCK) {
                size = -1;
            } else {
                size = 0;
            }
        }
        return size;
    }

    int32_t read_from(
        pump_socket fd,
        block_t *b, 
        int32_t size, 
        struct sockaddr *addr, 
        int32_t *addrlen) {
        size = ::recvfrom(fd, b, size, 0, (struct sockaddr*)addr, (socklen_t*)addrlen);
        if (size < 0) {
            int32_t ec = net::last_errno();
            if (ec == LANE_EINPROGRESS || ec == LANE_EWOULDBLOCK) {
                size = -1;
            } else {
                size = 0;
            }
        }
        return size;
    }

    int32_t send(
        pump_socket fd,
        const block_t *b,
        int32_t size) {
        size = ::send(fd, b, size, 0);
        if (PUMP_LIKELY(size > 0)) {
            return size;
        } else if (size < 0) {
            int32_t ec = net::last_errno();
            if (ec == LANE_EINPROGRESS || ec == LANE_EWOULDBLOCK) {
                size = -1;
            } else {
                size = 0;
            }
        }
        return size;
    }

    int32_t send_to(
        pump_socket fd,
        const block_t *b, 
        int32_t size, 
        struct sockaddr *addr, 
        int32_t addrlen) {
        socklen_t len = addrlen;
        size = ::sendto(fd, b, size, 0, addr, len);
        if (size < 0) {
            int32_t ec = net::last_errno();
            if (ec == LANE_EINPROGRESS || ec == LANE_EWOULDBLOCK) {
                size = -1;
            } else {
                size = 0;
            }
        }
        return size;
    }

    void shutdown(pump_socket fd, int32_t how) {
        ::shutdown(fd, how);
    }

    bool close(pump_socket fd) {
#if defined(PUMP_HAVE_WINSOCK)
        return (::closesocket(fd) == 0);
#else
        return (::close(fd) == 0);
#endif
    }

    int32_t get_socket_error(pump_socket fd) {
        int32_t res = 0;
#if defined(PUMP_HAVE_WINSOCK)
        int32_t len = sizeof(res);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, (block_t*)&res, &len);
#else
        socklen_t len = sizeof(res);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &res, &len);
#endif
        return res;
    }

    int32_t last_errno() {
#if defined(PUMP_HAVE_WINSOCK)
        return WSAGetLastError();
#else
        return errno;
#endif
    }

    bool local_address(
        pump_socket fd, 
        struct sockaddr *addr, 
        int32_t *addrlen) {
        if (getsockname(fd, addr, (socklen_t*)addrlen) == 0) {
            return true;
        }
        PUMP_DEBUG_LOG("net: local_address failed %d", last_errno());
        PUMP_ASSERT(false);
        return false;
    }

    bool remote_address(
        pump_socket fd, 
        struct sockaddr *addr, 
        int32_t *addrlen) {
        if (getpeername(fd, addr, (socklen_t*)addrlen) == 0) {
            return true;
        }
        PUMP_DEBUG_LOG("net: remote_address failed %d", last_errno());
        PUMP_ASSERT(false);
        return false;
    }

    std::string address_to_string(
        struct sockaddr *addr, 
        int32_t addrlen) {
        char host[128] = {0};
        if (addrlen == sizeof(struct sockaddr_in)) {
            struct sockaddr_in *v4 = (struct sockaddr_in*)addr;
            if (inet_ntop(AF_INET, &(v4->sin_addr), host, sizeof(host)) != nullptr) {
                pump_snprintf(host + strlen(host), 10, ":%d", ntohs(v4->sin_port));
                return std::string(host);
            }
        } else {
            struct sockaddr_in6 *v6 = (struct sockaddr_in6*)addr;
            if (::inet_ntop(AF_INET6, &(v6->sin6_addr), host, sizeof(host)) != nullptr) {
                pump_snprintf(host + strlen(host), 10, ":%d", ntohs(v6->sin6_port));
                return std::string(host);
            }
        }
        PUMP_DEBUG_LOG("net: address_to_string failed");
        PUMP_ASSERT(false);
        return "";
    }

    bool string_to_address(
        const std::string &ip,
        uint16_t port,
        struct sockaddr *addr,
        int32_t *addrlen) {
        addrinfo hints;
        addrinfo *res = nullptr;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        hints.ai_flags = AI_NUMERICHOST;
        if (getaddrinfo(ip.c_str(), 0, &hints, &res) == 0) {
            struct sockaddr_in6 *v6 = (struct sockaddr_in6*)addr;
            *v6 = *(struct sockaddr_in6*)res->ai_addr;
            v6->sin6_port = htons(port);
            *addrlen = (int32_t)res->ai_addrlen;
            freeaddrinfo(res);
            return true;
        }

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        if (getaddrinfo(ip.c_str(), nullptr, &hints, &res) == 0) {
            struct sockaddr_in *v4 = (struct sockaddr_in*)addr;
            *v4 = *(struct sockaddr_in*)res->ai_addr;
            v4->sin_port = htons(port);
            *addrlen = (int32_t)res->ai_addrlen;
            freeaddrinfo(res);
            return true;
        }

        if (res) {
            freeaddrinfo(res);
        }

        PUMP_DEBUG_LOG("net: string_to_address failed");
        PUMP_ASSERT(false);
        return false;
    }

}  // namespace net
}  // namespace pump
