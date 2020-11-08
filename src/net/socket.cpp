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

    int32 create_socket(int32 domain, int32 type) {
        return (int32)::socket(domain, type, 0);
    }

    bool set_noblock(int32 fd, int32 noblock) {
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
        int32 flags = fcntl(fd, F_GETFL, 0);
        flags = (noblock == 0) ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
        if (fcntl(fd, F_SETFL, flags) != -1) {
            return true;
        }
#endif
        PUMP_WARN_LOG("net::set_noblock: with ec=%d", last_errno());
        return false;
    }

    bool set_linger(int32 fd, uint16 on, uint16 linger) {
        struct linger lgr;
        lgr.l_onoff = on;
        lgr.l_linger = linger;
        if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (c_block_ptr)&lgr, sizeof(lgr)) == 0) {
            return true;
        }

        PUMP_WARN_LOG("net::set_linger: with ec=%d", last_errno());
        return false;
    }

    bool set_read_bs(int32 fd, int32 size) {
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (c_block_ptr)&size, sizeof(size)) == 0) {
            return true;
        }

        PUMP_WARN_LOG("net::set_read_bs: with ec=%d", last_errno());
        return false;
    }

    bool set_send_bs(int32 fd, int32 size) {
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (c_block_ptr)&size, sizeof(size)) == 0) {
            return true;
        }

        PUMP_WARN_LOG("net::set_send_bs: with ec=%d", last_errno());
        return false;
    }

    bool set_keeplive(int32 fd, int32 keeplive, int32 interval) {
        int32 on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&on, sizeof(on)) == -1) {
            PUMP_WARN_LOG(
                "net::set_keeplive: setsockopt SO_KEEPALIVE with ec=%d", last_errno());
            return false;
        }

#if defined(PUMP_HAVE_WINSOCK)
        DWORD bytes = 0;
        struct tcp_keepalive keepalive;
        keepalive.onoff = 1;
        keepalive.keepalivetime = keeplive * 1000;
        keepalive.keepaliveinterval = interval * 1000;
        if (WSAIoctl(fd,
                     SIO_KEEPALIVE_VALS,
                     &keepalive,
                     sizeof(keepalive),
                     nullptr,
                     0,
                     &bytes,
                     nullptr,
                     nullptr) == -1) {
            PUMP_ERR_LOG(
                "net::set_keeplive: WSAIoctl SIO_KEEPALIVE_VALS with ec=%d", last_errno());
            return false;
        }
#else
        int32 count = 3;
        if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &keeplive, sizeof(keeplive)) == -1 ||
            setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)) == -1 ||
            setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &count, sizeof(count)) == -1) {
            PUMP_WARN_LOG(
                "net::set_keeplive: setsockopt TCP_KEEPINTVL with ec=%d", last_errno());
            return false;
        }
#endif
        return true;
    }

    bool set_reuse(int32 fd, int32 reuse) {
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (c_block_ptr)&reuse, sizeof(reuse)) == 0) {
            return true;
        }

        PUMP_WARN_LOG("net::set_reuse: with ec=%d", last_errno());
        return false;
    }

    bool set_nodelay(int32 fd, int32 nodelay) {
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (c_block_ptr)&nodelay, sizeof(nodelay)) == 0) {
            return true;
        }

        PUMP_ERR_LOG("net::set_nodelay: with ec=%d", last_errno());
        return false;
    }

    bool update_connect_context(int32 fd) {
#if defined(PUMP_HAVE_WINSOCK)
        if (setsockopt(fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr, 0) == 0) {
            return true;
        }

        PUMP_WARN_LOG("net::update_connect_context: with ec=%d", last_errno());
        return false;
#else
        return true;
#endif
    }

    bool set_udp_conn_reset(int32 fd, bool enable) {
#if defined(PUMP_HAVE_WINSOCK)
        DWORD bytes_returned = 0;
        BOOL behavior = enable ? TRUE : FALSE;
        if (WSAIoctl(fd,
                     SIO_UDP_CONNRESET,
                     &behavior,
                     sizeof(behavior),
                     nullptr,
                     0,
                     &bytes_returned,
                     nullptr,
                     nullptr) == SOCKET_ERROR &&
            last_errno() != WSAEWOULDBLOCK) {
            PUMP_WARN_LOG("net::set_udp_conn_reset: with ec=%d", last_errno());
            return false;
        }
#endif
        return true;
    }

    bool bind(int32 fd, struct sockaddr *addr, int32 addrlen) {
        if (::bind(fd, addr, addrlen) == 0) {
            return true;
        }

        PUMP_WARN_LOG("net::bind: with ec=%d", last_errno());
        return false;
    }

    bool listen(int32 fd, int32 backlog) {
        if (::listen(fd, backlog) == 0) {
            return true;
        }

        PUMP_WARN_LOG("net::listen: with ec=%d", last_errno());
        return false;
    }

    int32 accept(int32 fd, struct sockaddr *addr, int32_ptr addrlen) {
        int32 client = (int32)::accept(fd, addr, (socklen_t *)addrlen);
        if (client < 0) {
            PUMP_WARN_LOG("net::accept: with ec=%d", last_errno());
        }
        return client;
    }

    bool connect(int32 fd, struct sockaddr *addr, int32 addrlen) {
        if (::connect(fd, addr, addrlen) != 0) {
            int32 ec = net::last_errno();
            if (ec != LANE_EALREADY && 
                ec != LANE_EWOULDBLOCK && 
                ec != LANE_EINPROGRESS) {
                PUMP_WARN_LOG("net::connect: with ec=%d", ec);
                return false;
            }
        }
        return true;
    }

    int32 read(int32 fd, block_ptr b, int32 size) {
        size = ::recv(fd, b, size, 0);
        if (PUMP_LIKELY(size > 0)) {
            return size;
        } else if (size < 0) {
           int32 ec = net::last_errno();
            if (ec == LANE_EINPROGRESS || 
                ec == LANE_EWOULDBLOCK) {
                size = -1;
            } else {
                size = 0;
            }
        }
        return size;
    }

    int32 read_from(
        int32 fd, block_ptr b, int32 size, struct sockaddr *addr, int32_ptr addrlen) {
        size = ::recvfrom(fd, b, size, 0, (struct sockaddr *)addr, (socklen_t *)addrlen);
        if (size < 0) {
            int32 ec = net::last_errno();
            if (ec == LANE_EINPROGRESS || 
                ec == LANE_EWOULDBLOCK) {
                size = -1;
            } else {
                size = 0;
            }
        }
        return size;
    }

    int32 send(int32 fd, c_block_ptr b, int32 size) {
        size = ::send(fd, b, size, 0);
        if (PUMP_LIKELY(size > 0)) {
            return size;
        } else if (size < 0) {
            int32 ec = net::last_errno();
            if (ec == LANE_EINPROGRESS || 
                ec == LANE_EWOULDBLOCK) {
                size = -1;
            } else {
                size = 0;
            }
        }
        return size;
    }

    int32 send_to(
        int32 fd, c_block_ptr b, int32 size, struct sockaddr *addr, int32 addrlen) {
        socklen_t len = addrlen;
        size = ::sendto(fd, b, size, 0, addr, len);
        if (size < 0) {
            int32 ec = net::last_errno();
            if (ec == LANE_EINPROGRESS || 
                ec == LANE_EWOULDBLOCK) {
                size = -1;
            } else {
                size = 0;
            }
        }
        return size;
    }

    int32 poll(struct pollfd *pfds, int32 count, int32 timeout) {
#if defined(PUMP_HAVE_WINSOCK)
        return ::WSAPoll(pfds, count, timeout);
#else
        return ::poll(pfds, count, timeout);
#endif
    }

    void shutdown(int32 fd) {
        ::shutdown(fd, 0);
    }

    bool close(int32 fd) {
#if defined(PUMP_HAVE_WINSOCK)
        return (::closesocket(fd) == 0);
#else
        return (::close(fd) == 0);
#endif
    }

    int32 get_socket_error(int32 fd) {
        int32 res = 0;
#if defined(PUMP_HAVE_WINSOCK)
        int32 len = sizeof(res);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&res, &len);
#else
        socklen_t len = sizeof(res);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &res, &len);
#endif
        return res;
    }

    int32 last_errno() {
#if defined(OS_WINDOWS)
        return WSAGetLastError();
#else
        return errno;
#endif
    }

    bool local_address(int32 fd, struct sockaddr *addr, int32_ptr addrlen) {
        if (getsockname(fd, addr, (socklen_t*)addrlen) == 0) {
            return true;
        }

        PUMP_WARN_LOG("net::local_address: with ec=%d", last_errno());
        return false;
    }

    bool remote_address(int32 fd, struct sockaddr *addr, int32_ptr addrlen) {
        if (getpeername(fd, addr, (socklen_t*)addrlen) == 0) {
            return true;
        }

        PUMP_WARN_LOG("net::remote_address: with ec=%d", last_errno());
        return false;
    }

    std::string address_to_string(struct sockaddr *addr, int32 addrlen) {
        char host[128] = {0};
        if (addrlen == sizeof(struct sockaddr_in)) {
            struct sockaddr_in *v4 = (struct sockaddr_in *)addr;
            if (inet_ntop(AF_INET, &(v4->sin_addr), host, sizeof(host)) != nullptr) {
                pump_snprintf(host + strlen(host), 10, ":%d", ntohs(v4->sin_port));
                return std::string(host);
            }
        } else {
            struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)addr;
            if (::inet_ntop(AF_INET6, &(v6->sin6_addr), host, sizeof(host)) != nullptr) {
                pump_snprintf(host + strlen(host), 10, ":%d", ntohs(v6->sin6_port));
                return std::string(host);
            }
        }

        PUMP_WARN_LOG("net::address_to_string");
        return "";
    }

    bool string_to_address(const std::string &ip,
                           uint16 port,
                           struct sockaddr *addr,
                           int32_ptr addrlen) {
        addrinfo hints;
        addrinfo *res = nullptr;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        hints.ai_flags = AI_NUMERICHOST;
        if (getaddrinfo(ip.c_str(), 0, &hints, &res) == 0) {
            struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)addr;
            *v6 = *(struct sockaddr_in6 *)res->ai_addr;
            v6->sin6_port = htons(port);
            *addrlen = (int32)res->ai_addrlen;
            freeaddrinfo(res);
            return true;
        }

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        if (getaddrinfo(ip.c_str(), nullptr, &hints, &res) == 0) {
            struct sockaddr_in *v4 = (struct sockaddr_in *)addr;
            *v4 = *(struct sockaddr_in *)res->ai_addr;
            v4->sin_port = htons(port);
            *addrlen = (int32)res->ai_addrlen;
            freeaddrinfo(res);
            return true;
        }

        if (res) {
            freeaddrinfo(res);
        }

        PUMP_WARN_LOG("net::string_to_address: address=%s:%d", ip.c_str(), port);
        return false;
    }

}  // namespace net
}  // namespace pump
