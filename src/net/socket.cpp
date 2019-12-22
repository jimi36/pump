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

#include "librabbit/net/socket.h"

namespace librabbit {
	namespace net {

		int32 create_socket(int32 domain, int32 type)
		{
			return (int32)::socket(domain, type, 0);
		}

		bool set_noblock(int32 fd, int32 noblock)
		{
#ifdef WIN32
			u_long mode = (noblock == 0) ? 0 : 1;  //non-blocking mode
			return ::ioctlsocket(fd, FIONBIO, &mode) != SOCKET_ERROR;
#else
			int32 flags = fcntl(fd, F_GETFL, 0);
			flags = (noblock == 0) ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
			return ::fcntl(fd, F_SETFL, flags) != -1;
#endif
		}

		bool set_linger(int32 fd, uint16 on, uint16 linger)
		{
			struct linger lgr;
			lgr.l_onoff = on;
			lgr.l_linger = linger;
			return (::setsockopt(fd, SOL_SOCKET, SO_LINGER, (const int8*)&lgr, sizeof(lgr)) == 0);
		}

		bool set_recv_buf(int32 fd, int32 size)
		{
			return (::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char*)&size, sizeof(int32)) == 0);
		}

		bool set_send_buf(int32 fd, int32 size)
		{
			return (::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char*)&size, sizeof(int32)) == 0);
		}

		bool set_keeplive(int32 fd, int32 keeplive, int32 keepinterval)
		{
			int32 on = 1;
			if (::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&on, sizeof(on)) == -1)
				return false;

#ifdef WIN32
			DWORD bytes = 0;
			struct tcp_keepalive keepalive;
			keepalive.onoff = 1;
			keepalive.keepalivetime = keeplive * 1000;
			keepalive.keepaliveinterval = keepinterval * 1000;
			if (::WSAIoctl(fd, SIO_KEEPALIVE_VALS, &keepalive, sizeof(keepalive), nullptr, 0, &bytes, nullptr, nullptr) == -1)
				return false;
#else
			int32 keepcount = 3;
			if (::setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &keeplive, sizeof(keeplive)) == -1 ||
				::setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &keepinterval, sizeof(keepinterval)) == -1 ||
				::setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &keepcount, sizeof(keepcount)) == -1)
				return false;
#endif
			return true;
		}

		bool set_reuse(int32 fd, int32 reuse)
		{
			return (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) == 0);
		}

		bool set_nodelay(int32 fd, int32 nodelay)
		{
			return (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay)) == 0);
		}

		bool update_connect_context(int32 fd)
		{
			return (::setsockopt(fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr, 0) == 0);
		}

		bool set_udp_conn_reset(int32 fd, bool enable)
		{
#ifdef WIN32
			DWORD bytes_returned = 0;
			BOOL behavior = enable ? TRUE : FALSE;
			if (WSAIoctl(fd, SIO_UDP_CONNRESET, &behavior, sizeof(behavior), nullptr, 0, &bytes_returned, nullptr, nullptr) == SOCKET_ERROR)
			{
				int32 ec = last_errno();
				if (ec != WSAEWOULDBLOCK)
					return false;
			}
#endif
			return true;
		}

		bool bind(int32 fd, struct sockaddr *addr, int32 addrlen)
		{
			return (::bind(fd, addr, addrlen) == 0);
		}

		bool listen(int32 fd, int32 backlog)
		{
			return (::listen(fd, backlog) == 0);
		}

		int32 accept(int32 fd, struct sockaddr *addr, int32_ptr addrlen)
		{
			return (int32)::accept(fd, addr, (socklen_t*)addrlen);
		}

		bool connect(int32 fd, struct sockaddr *addr, int32 addrlen)
		{
			return (::connect(fd, addr, addrlen) == 0);
		}

		int32 recv(int32 fd, block_ptr b, uint32 size)
		{
			return ::recv(fd, b, size, 0);
		}

		int32 read_from(int32 fd, block_ptr b, uint32 size, struct sockaddr *addr, int32_ptr addrlen)
		{
			return ::recvfrom(fd, b, size, 0, (struct sockaddr*)addr, (socklen_t*)addrlen);
		}

		int32 send(int32 fd, c_block_ptr b, uint32 size)
		{
			return ::send(fd, b, size, 0);
		}

		int32 write_to(int32 fd, c_block_ptr b, uint32 size, struct sockaddr *addr, int32 addrlen)
		{
			socklen_t len = addrlen;
			return ::sendto(fd, b, size, 0, addr, len);
		}

		int32 poll(struct pollfd *pfds, int32 count, int32 timeout)
		{
#ifdef WIN32
			return ::WSAPoll(pfds, count, timeout);
#else
			return ::poll(pfds, count, timeout);
#endif

		}

		void shutdown(int32 fd)
		{
			::shutdown(fd, 0);
		}

		bool close(int32 fd)
		{
#ifdef WIN32
			return (::closesocket(fd) == 0);
#else
			return (::close(fd) == 0);
#endif
		}

		int32 get_socket_error(int32 fd)
		{
			int32 res = 0;
#ifdef WIN32
			int32 len = sizeof(res);
			::getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&res, &len);
#else
			socklen_t len = sizeof(res);
			::getsockopt(fd, SOL_SOCKET, SO_ERROR, &res, &len);
#endif
			return res;
		}

		int32 last_errno()
		{
#ifdef WIN32
			return ::WSAGetLastError();
#else
			return last_errno;
#endif
		}

		bool local_address(int32 fd, struct sockaddr *addr, int32_ptr addrlen)
		{
			return (::getsockname(fd, addr, (socklen_t*)addrlen) == 0);
		}

		bool remote_address(int32 fd, struct sockaddr *addr, int32_ptr addrlen)
		{
			return (::getpeername(fd, addr, (socklen_t*)addrlen) == 0);
		}

		std::string address_to_string(struct sockaddr *addr, int32 addrlen)
		{
			char host[128] = { 0 };
			if (addrlen == sizeof(struct sockaddr_in))
			{
				struct sockaddr_in *v4 = (struct sockaddr_in*)addr;
				if (::inet_ntop(AF_INET, &(v4->sin_addr), host, sizeof(host)) != nullptr)
				{
					snprintf(host + strlen(host), 10, ":%d", ntohs(v4->sin_port));
					return std::string(host);
				}
			}
			else
			{
				struct sockaddr_in6 *v6 = (struct sockaddr_in6*)addr;
				if (::inet_ntop(AF_INET6, &(v6->sin6_addr), host, sizeof(host)) != nullptr)
				{
					snprintf(host + strlen(host), 10, ":%d", ntohs(v6->sin6_port));
					return std::string(host);
				}
			}
			return "";
		}

		bool string_to_address(const std::string& ip, uint16 port, struct sockaddr *addr, int32_ptr addrlen)
		{
			addrinfo hints;
			addrinfo *res = nullptr;

			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_INET6;
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_protocol = IPPROTO_UDP;
			hints.ai_flags = AI_NUMERICHOST;
			if (getaddrinfo(ip.c_str(), 0, &hints, &res) == 0)
			{
				struct sockaddr_in6 *v6 = (struct sockaddr_in6*)addr;
				*v6 = *(struct sockaddr_in6*)res->ai_addr;
				v6->sin6_port = htons(port);
				*addrlen = (int32)res->ai_addrlen;
				freeaddrinfo(res);
				return true;
			}

			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_protocol = IPPROTO_UDP;
			if (getaddrinfo(ip.c_str(), nullptr, &hints, &res) == 0)
			{
				struct sockaddr_in *v4 = (struct sockaddr_in*)addr;
				*v4 = *(struct sockaddr_in*)res->ai_addr;
				v4->sin_port = htons(port);
				*addrlen = (int32)res->ai_addrlen;
				freeaddrinfo(res);
				return true;
			}

			if (res)
				freeaddrinfo(res);

			return false;
		}

	}
}