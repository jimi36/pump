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

#include "pump/deps.h"
#include "pump/net/iocp.h"
#include "pump/net/error.h"


#define MUT_MAX_SIZE 1400

#define ADDRESS_MAX_LEN 64

namespace pump {
	namespace net {

		/*********************************************************************************
		 * Create socket file descriptor
		 ********************************************************************************/
		LIB_EXPORT int32 create_socket(int32 domain, int32 type);

		/*********************************************************************************
		 * Set nonblock flag
		 ********************************************************************************/
		LIB_EXPORT bool set_noblock(int32 fd, int32 noblock);

		/*********************************************************************************
		 * Set linger flag
		 ********************************************************************************/
		LIB_EXPORT bool set_linger(int32 fd, uint16 on, uint16 linger);

		/*********************************************************************************
		 * Set receive buffer size
		 ********************************************************************************/
		LIB_EXPORT bool set_recv_buf(int32 fd, int32 size);

		/*********************************************************************************
		 * Set send buffer size
		 ********************************************************************************/
		LIB_EXPORT bool set_send_buf(int32 fd, int32 size);

		/*********************************************************************************
		 * Set tcp keeplive
		 ********************************************************************************/
		LIB_EXPORT bool set_keeplive(int32 fd, int32 keeplive, int32 keepinterval);

		/*********************************************************************************
		 * Set reuse address
		 ********************************************************************************/
		LIB_EXPORT bool set_reuse(int32 fd, int32 reuse);

		/*********************************************************************************
		 * Set tcp no delay
		 ********************************************************************************/
		LIB_EXPORT bool set_nodelay(int32 fd, int32 nodelay);

		/*********************************************************************************
		 * Update connect context
		 ********************************************************************************/
		LIB_EXPORT bool update_connect_context(int32 fd);

		/*********************************************************************************
		 * Set udp connection reset
		 * This is for windows system, other system will return true
		 ********************************************************************************/
		LIB_EXPORT bool set_udp_conn_reset(int32 fd, bool enable);

		/*********************************************************************************
		 * Bind address
		 ********************************************************************************/
		LIB_EXPORT bool bind(int32 fd, struct sockaddr *addr, int32 addrlen);

		/*********************************************************************************
		 * Listen socket
		 ********************************************************************************/
		LIB_EXPORT bool listen(int32 fd, int32 backlog = 65535);

		/*********************************************************************************
		 * Accept socket
		 ********************************************************************************/
		LIB_EXPORT int32 accept(int32 fd, struct sockaddr *addr, int32_ptr addrlen);

		/*********************************************************************************
		 * Connect
		 ********************************************************************************/
		LIB_EXPORT bool connect(int32 fd, struct sockaddr *addr, int32 addrlen);

		/*********************************************************************************
		 * Read
		 ********************************************************************************/
		LIB_EXPORT int32 read(int32 fd, block_ptr b, uint32 size);

		/*********************************************************************************
		 * Readfrom
		 ********************************************************************************/
		LIB_EXPORT int32 read_from(int32 fd, block_ptr b, uint32 size, struct sockaddr *addr, int32_ptr addrlen);

		/*********************************************************************************
		 * Send
		 ********************************************************************************/
		LIB_EXPORT int32 send(int32 fd, c_block_ptr b, uint32 size);

		/*********************************************************************************
		 * Sendto
		 ********************************************************************************/
		LIB_EXPORT int32 send_to(int32 fd, c_block_ptr b, uint32 size, struct sockaddr *addr, int32 addrlen);

		/*********************************************************************************
		 * Poll a socket events
		 ********************************************************************************/
		LIB_EXPORT int32 poll(struct pollfd *pfds, int32 count, int32 timeout);

		/*********************************************************************************
		 * Close the ability of writing
		 ********************************************************************************/
		LIB_EXPORT void shutdown(int32 fd);

		/*********************************************************************************
		 * Close socket
		 ********************************************************************************/
		LIB_EXPORT bool close(int32 fd);

		/*********************************************************************************
		 * Get socket error
		 ********************************************************************************/
		LIB_EXPORT int32 get_socket_error(int32 fd);

		/*********************************************************************************
		 * Get last errno
		 ********************************************************************************/
		LIB_EXPORT int32 last_errno();

		/*********************************************************************************
		 * Get local address of the socket
		 ********************************************************************************/
		LIB_EXPORT bool local_address(int32 fd, struct sockaddr *addr, int32_ptr addrlen);

		/*********************************************************************************
		 * Get remote address of the socket
		 ********************************************************************************/
		LIB_EXPORT bool remote_address(int32 fd, struct sockaddr *addr, int32_ptr addrlen);

		/*********************************************************************************
		 * Transfrom address to string
		 * On success return string address like 127.0.0.1:80, else return empty string
		 ********************************************************************************/
		LIB_EXPORT std::string address_to_string(struct sockaddr *addr, int32 addrlen);

		/*********************************************************************************
		 * Transfrom string to address
		 ********************************************************************************/
		LIB_EXPORT bool string_to_address(const std::string &ip, uint16 port, struct sockaddr *addr, int32_ptr addrlen);

	}
}

#endif