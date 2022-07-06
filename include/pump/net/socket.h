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
#include <winioctl.h>
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

#if defined(PUMP_HAVE_WINSOCK)
#define pump_socket SOCKET
#else
#define pump_socket int32_t
#endif

#if defined(PUMP_HAVE_WINSOCK)
#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND
#define SHUT_RDWR SD_BOTH
#endif

#if defined(INVALID_SOCKET)
#define invalid_socket INVALID_SOCKET
#else
#define invalid_socket -1
#endif

namespace pump {
namespace net {

/*********************************************************************************
 * Create socket file descriptor
 ********************************************************************************/
pump_lib pump_socket create_socket(int32_t domain, int32_t type);

/*********************************************************************************
 * Set nonblock flag
 ********************************************************************************/
pump_lib bool set_noblock(pump_socket fd, int32_t noblock);

/*********************************************************************************
 * Set linger flag
 ********************************************************************************/
pump_lib bool set_linger(
    pump_socket fd,
    uint16_t on,
    uint16_t linger);

/*********************************************************************************
 * Set read buffer size
 ********************************************************************************/
pump_lib bool set_read_bs(pump_socket fd, int32_t size);

/*********************************************************************************
 * Set send buffer size
 ********************************************************************************/
pump_lib bool set_send_bs(pump_socket fd, int32_t size);

/*********************************************************************************
 * Set tcp keeplive
 ********************************************************************************/
pump_lib bool set_keeplive(
    pump_socket fd,
    int32_t keeplive,
    int32_t keepinterval);

/*********************************************************************************
 * Set reuse address
 ********************************************************************************/
pump_lib bool set_reuse(pump_socket fd, int32_t reuse);

/*********************************************************************************
 * Set tcp no delay
 ********************************************************************************/
pump_lib bool set_nodelay(pump_socket fd, int32_t nodelay);

/*********************************************************************************
 * Update connect context
 ********************************************************************************/
pump_lib bool update_connect_context(pump_socket fd);

/*********************************************************************************
 * Set udp connection reset
 * This is for windows system, other system will return true
 ********************************************************************************/
pump_lib bool set_udp_conn_reset(pump_socket fd, bool enable);

/*********************************************************************************
 * Bind address
 ********************************************************************************/
pump_lib bool bind(
    pump_socket fd,
    struct sockaddr *addr,
    int32_t addrlen);

/*********************************************************************************
 * Listen socket
 ********************************************************************************/
pump_lib bool listen(pump_socket fd, int32_t backlog = 65535);

/*********************************************************************************
 * Accept socket
 ********************************************************************************/
pump_lib pump_socket accept(
    pump_socket fd,
    struct sockaddr *addr,
    int32_t *addrlen);

/*********************************************************************************
 * Connect
 ********************************************************************************/
pump_lib bool connect(
    pump_socket fd,
    struct sockaddr *addr,
    int32_t addrlen);

/*********************************************************************************
 * Read
 ********************************************************************************/
pump_lib int32_t read(
    pump_socket fd,
    char *b,
    int32_t size);

/*********************************************************************************
 * Readfrom
 ********************************************************************************/
pump_lib int32_t read_from(
    pump_socket fd,
    char *b,
    int32_t size,
    struct sockaddr *addr,
    int32_t *addrlen);

/*********************************************************************************
 * Send
 ********************************************************************************/
pump_lib int32_t send(
    pump_socket fd,
    const char *b,
    int32_t size);

/*********************************************************************************
 * Sendto
 ********************************************************************************/
pump_lib int32_t send_to(
    pump_socket fd,
    const char *b,
    int32_t size,
    struct sockaddr *addr,
    int32_t addrlen);

/*********************************************************************************
 * Close the ability of writing
 ********************************************************************************/
pump_lib void shutdown(pump_socket fd, int32_t how);

/*********************************************************************************
 * Close socket
 ********************************************************************************/
pump_lib bool close(pump_socket fd);

/*********************************************************************************
 * Get socket error
 ********************************************************************************/
pump_lib int32_t get_socket_error(pump_socket fd);

/*********************************************************************************
 * Get last errno
 ********************************************************************************/
pump_lib int32_t last_errno();

/*********************************************************************************
 * Get local address of the socket
 ********************************************************************************/
pump_lib bool local_address(
    pump_socket fd,
    struct sockaddr *addr,
    int32_t *addrlen);

/*********************************************************************************
 * Get remote address of the socket
 ********************************************************************************/
pump_lib bool remote_address(
    pump_socket fd,
    struct sockaddr *addr,
    int32_t *addrlen);

/*********************************************************************************
 * Transfrom address to string
 * On success return string address like 127.0.0.1:80, else return empty
 *string
 ********************************************************************************/
pump_lib std::string address_to_string(struct sockaddr *addr, int32_t addrlen);

/*********************************************************************************
 * Transfrom string to address
 ********************************************************************************/
pump_lib bool string_to_address(
    const std::string &ip,
    uint16_t port,
    struct sockaddr *addr,
    int32_t *addrlen);

}  // namespace net
}  // namespace pump

#endif