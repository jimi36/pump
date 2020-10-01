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

#ifndef pump_net_sockets_h
#define pump_net_sockets_h

#include "pump/config.h"

#if defined(OS_WINDOWS)
#include <winsock2.h>
#include <mstcpip.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#else
#include <poll.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#include <string>

#include "pump/types.h"
#include "pump/platform.h"

namespace pump {
namespace net {

    /*********************************************************************************
     * Create socket file descriptor
     ********************************************************************************/
    int32 create_socket(int32 domain, int32 type);

    /*********************************************************************************
     * Set nonblock flag
     ********************************************************************************/
    bool set_noblock(int32 fd, int32 noblock);

    /*********************************************************************************
     * Set linger flag
     ********************************************************************************/
    bool set_linger(int32 fd, uint16 on, uint16 linger);

    /*********************************************************************************
     * Set read buffer size
     ********************************************************************************/
    bool set_read_bs(int32 fd, int32 size);

    /*********************************************************************************
     * Set send buffer size
     ********************************************************************************/
    bool set_send_bs(int32 fd, int32 size);

    /*********************************************************************************
     * Set tcp keeplive
     ********************************************************************************/
    bool set_keeplive(int32 fd, int32 keeplive, int32 keepinterval);

    /*********************************************************************************
     * Set reuse address
     ********************************************************************************/
    bool set_reuse(int32 fd, int32 reuse);

    /*********************************************************************************
     * Set tcp no delay
     ********************************************************************************/
    bool set_nodelay(int32 fd, int32 nodelay);

    /*********************************************************************************
     * Update connect context
     ********************************************************************************/
    bool update_connect_context(int32 fd);

    /*********************************************************************************
     * Set udp connection reset
     * This is for windows system, other system will return true
     ********************************************************************************/
    bool set_udp_conn_reset(int32 fd, bool enable);

    /*********************************************************************************
     * Bind address
     ********************************************************************************/
    bool bind(int32 fd, struct sockaddr *addr, int32 addrlen);

    /*********************************************************************************
     * Listen socket
     ********************************************************************************/
    bool listen(int32 fd, int32 backlog = 65535);

    /*********************************************************************************
     * Accept socket
     ********************************************************************************/
    int32 accept(int32 fd, struct sockaddr *addr, int32_ptr addrlen);

    /*********************************************************************************
     * Connect
     ********************************************************************************/
    bool connect(int32 fd, struct sockaddr *addr, int32 addrlen);

    /*********************************************************************************
     * Read
     ********************************************************************************/
    int32 read(int32 fd, block_ptr b, int32 size);

    /*********************************************************************************
     * Readfrom
     ********************************************************************************/
    int32 read_from(
        int32 fd, block_ptr b, int32 size, struct sockaddr *addr, int32_ptr addrlen);

    /*********************************************************************************
     * Send
     ********************************************************************************/
    int32 send(int32 fd, c_block_ptr b, int32 size);

    /*********************************************************************************
     * Sendto
     ********************************************************************************/
    int32 send_to(
        int32 fd, c_block_ptr b, int32 size, struct sockaddr *addr, int32 addrlen);

    /*********************************************************************************
     * Poll a socket events
     ********************************************************************************/
    int32 poll(struct pollfd *pfds, int32 count, int32 timeout);

    /*********************************************************************************
     * Close the ability of writing
     ********************************************************************************/
    void shutdown(int32 fd);

    /*********************************************************************************
     * Close socket
     ********************************************************************************/
    bool close(int32 fd);

    /*********************************************************************************
     * Get socket error
     ********************************************************************************/
    int32 get_socket_error(int32 fd);

    /*********************************************************************************
     * Get last errno
     ********************************************************************************/
    int32 last_errno();

    /*********************************************************************************
     * Get local address of the socket
     ********************************************************************************/
    bool local_address(int32 fd, struct sockaddr *addr, int32_ptr addrlen);

    /*********************************************************************************
     * Get remote address of the socket
     ********************************************************************************/
    bool remote_address(int32 fd, struct sockaddr *addr, int32_ptr addrlen);

    /*********************************************************************************
     * Transfrom address to string
     * On success return string address like 127.0.0.1:80, else return empty
     *string
     ********************************************************************************/
    std::string address_to_string(struct sockaddr *addr, int32 addrlen);

    /*********************************************************************************
     * Transfrom string to address
     ********************************************************************************/
    bool string_to_address(const std::string &ip,
                           uint16 port,
                           struct sockaddr *addr,
                           int32_ptr addrlen);

}  // namespace net
}  // namespace pump

#endif