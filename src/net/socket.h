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

#include "error.h"

namespace pump {
	namespace net {

		/*********************************************************************************
		 * Create socket file descriptor
		 ********************************************************************************/
		PUMP_INLINE int32 create_socket(int32 domain, int32 type)
		{ return (int32)::socket(domain, type, 0); }

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
		PUMP_INLINE bool set_read_bs(int32 fd, int32 size)
		{
			return ::setsockopt(
				fd, 
				SOL_SOCKET, 
				SO_RCVBUF, 
				(c_block_ptr)&size, 
				sizeof(int32)
			) == 0;
		}

		/*********************************************************************************
		 * Set send buffer size
		 ********************************************************************************/
		PUMP_INLINE bool set_send_bs(int32 fd, int32 size)
		{
			return ::setsockopt(
				fd, 
				SOL_SOCKET, 
				SO_SNDBUF, 
				(c_block_ptr)&size, 
				sizeof(int32)
			) == 0;
		}

		/*********************************************************************************
		 * Set tcp keeplive
		 ********************************************************************************/
		bool set_keeplive(int32 fd, int32 keeplive, int32 keepinterval);

		/*********************************************************************************
		 * Set reuse address
		 ********************************************************************************/
		PUMP_INLINE bool set_reuse(int32 fd, int32 reuse)
		{
			return ::setsockopt(
				fd, 
				SOL_SOCKET, 
				SO_REUSEADDR, 
				(c_block_ptr)&reuse, 
				sizeof(reuse)
			) == 0;
		}

		/*********************************************************************************
		 * Set tcp no delay
		 ********************************************************************************/
		PUMP_INLINE bool set_nodelay(int32 fd, int32 nodelay)
		{
			return ::setsockopt(
				fd, 
				IPPROTO_TCP, 
				TCP_NODELAY, 
				(c_block_ptr)&nodelay, 
				sizeof(nodelay)
			) == 0;
		}

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
		PUMP_INLINE bool bind(int32 fd, struct sockaddr *addr, int32 addrlen) 
		{ return ::bind(fd, addr, addrlen) == 0;}

		/*********************************************************************************
		 * Listen socket
		 ********************************************************************************/
		PUMP_INLINE bool listen(int32 fd, int32 backlog = 65535)
		{ return (::listen(fd, backlog) == 0); }

		/*********************************************************************************
		 * Accept socket
		 ********************************************************************************/
		PUMP_INLINE int32 accept(int32 fd, struct sockaddr *addr, int32_ptr addrlen)
		{ return (int32)::accept(fd, addr, (socklen_t*)addrlen); }

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
			int32 fd,
			block_ptr b,
			int32 size,
			struct sockaddr *addr,
			int32_ptr addrlen
		);

		/*********************************************************************************
		 * Send
		 ********************************************************************************/
		int32 send(int32 fd, c_block_ptr b, int32 size);

		/*********************************************************************************
		 * Sendto
		 ********************************************************************************/
		int32 send_to(
			int32 fd, 
			c_block_ptr b, 
			int32 size, 
			struct sockaddr *addr, 
			int32 addrlen
		);

		/*********************************************************************************
		 * Poll a socket events
		 ********************************************************************************/
		int32 poll(struct pollfd *pfds, int32 count, int32 timeout);

		/*********************************************************************************
		 * Close the ability of writing
		 ********************************************************************************/
		PUMP_INLINE void shutdown(int32 fd)
		{ ::shutdown(fd, 0); }

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
		PUMP_INLINE bool local_address(int32 fd, struct sockaddr *addr, int32_ptr addrlen) 
		{ return ::getsockname(fd, addr, (socklen_t*)addrlen) == 0; }

		/*********************************************************************************
		 * Get remote address of the socket
		 ********************************************************************************/
		PUMP_INLINE bool remote_address(int32 fd, struct sockaddr *addr, int32_ptr addrlen) 
		{ return ::getpeername(fd, addr, (socklen_t*)addrlen) == 0; }

		/*********************************************************************************
		 * Transfrom address to string
		 * On success return string address like 127.0.0.1:80, else return empty string
		 ********************************************************************************/
		std::string address_to_string(struct sockaddr *addr, int32 addrlen);

		/*********************************************************************************
		 * Transfrom string to address
		 ********************************************************************************/
		bool string_to_address(
			const std::string &ip,
			uint16 port, 
			struct sockaddr *addr, 
			int32_ptr addrlen
		);

	}
}

#endif