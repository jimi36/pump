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

#include "pump/types.h"

#include <string>

#if defined(PUMP_HAVE_WINSOCK)
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

namespace pump {
namespace net {

    /*********************************************************************************
     * Create socket file descriptor
     ********************************************************************************/
    int32_t create_socket(int32_t domain, int32_t type);

    /*********************************************************************************
     * Set nonblock flag
     ********************************************************************************/
    bool set_noblock(int32_t fd, int32_t noblock);

    /*********************************************************************************
     * Set linger flag
     ********************************************************************************/
    bool set_linger(int32_t fd, uint16_t on, uint16_t linger);

    /*********************************************************************************
     * Set read buffer size
     ********************************************************************************/
    bool set_read_bs(int32_t fd, int32_t size);

    /*********************************************************************************
     * Set send buffer size
     ********************************************************************************/
    bool set_send_bs(int32_t fd, int32_t size);

    /*********************************************************************************
     * Set tcp keeplive
     ********************************************************************************/
    bool set_keeplive(int32_t fd, int32_t keeplive, int32_t keepinterval);

    /*********************************************************************************
     * Set reuse address
     ********************************************************************************/
    bool set_reuse(int32_t fd, int32_t reuse);

    /*********************************************************************************
     * Set tcp no delay
     ********************************************************************************/
    bool set_nodelay(int32_t fd, int32_t nodelay);

    /*********************************************************************************
     * Update connect context
     ********************************************************************************/
    bool update_connect_context(int32_t fd);

    /*********************************************************************************
     * Set udp connection reset
     * This is for windows system, other system will return true
     ********************************************************************************/
    bool set_udp_conn_reset(int32_t fd, bool enable);

    /*********************************************************************************
     * Bind address
     ********************************************************************************/
    bool bind(int32_t fd, struct sockaddr *addr, int32_t addrlen);

    /*********************************************************************************
     * Listen socket
     ********************************************************************************/
    bool listen(int32_t fd, int32_t backlog = 65535);

    /*********************************************************************************
     * Accept socket
     ********************************************************************************/
    int32_t accept(int32_t fd, struct sockaddr *addr, int32_t *addrlen);

    /*********************************************************************************
     * Connect
     ********************************************************************************/
    bool connect(int32_t fd, struct sockaddr *addr, int32_t addrlen);

    /*********************************************************************************
     * Read
     ********************************************************************************/
    int32_t read(int32_t fd, block_t *b, int32_t size);

    /*********************************************************************************
     * Readfrom
     ********************************************************************************/
    int32_t read_from(int32_t fd, 
                      block_t *b, 
                      int32_t size, 
                      struct sockaddr *addr, 
                      int32_t *addrlen);

    /*********************************************************************************
     * Send
     ********************************************************************************/
    int32_t send(int32_t fd, const block_t *b, int32_t size);

    /*********************************************************************************
     * Sendto
     ********************************************************************************/
    int32_t send_to(int32_t fd, 
                    const block_t *b,
                    int32_t size, 
                    struct sockaddr *addr, 
                    int32_t addrlen);

    /*********************************************************************************
     * Poll a socket events
     ********************************************************************************/
    int32_t poll(struct pollfd *pfds, int32_t count, int32_t timeout);

    /*********************************************************************************
     * Close the ability of writing
     ********************************************************************************/
    void shutdown(int32_t fd);

    /*********************************************************************************
     * Close socket
     ********************************************************************************/
    bool close(int32_t fd);

    /*********************************************************************************
     * Get socket error
     ********************************************************************************/
    int32_t get_socket_error(int32_t fd);

    /*********************************************************************************
     * Get last errno
     ********************************************************************************/
    int32_t last_errno();

    /*********************************************************************************
     * Get local address of the socket
     ********************************************************************************/
    bool local_address(int32_t fd, struct sockaddr *addr, int32_t *addrlen);

    /*********************************************************************************
     * Get remote address of the socket
     ********************************************************************************/
    bool remote_address(int32_t fd, struct sockaddr *addr, int32_t *addrlen);

    /*********************************************************************************
     * Transfrom address to string
     * On success return string address like 127.0.0.1:80, else return empty
     *string
     ********************************************************************************/
    std::string address_to_string(struct sockaddr *addr, int32_t addrlen);

    /*********************************************************************************
     * Transfrom string to address
     ********************************************************************************/
    bool string_to_address(const std::string &ip,
                           uint16_t port,
                           struct sockaddr *addr,
                           int32_t *addrlen);

}  // namespace net
}  // namespace pump

#endif