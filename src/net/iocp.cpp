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

#include "pump/net/iocp.h"
#include "pump/net/socket.h"

namespace pump {
	namespace net {

		struct iocp_task
		{
#ifdef WIN32
			// IOCP overlapped
			WSAOVERLAPPED ol;
			// IOCP buffer
			WSABUF buf;
			// IOCP task type
			uint32 type;
			// IOCP processed size
			DWORD processed_size; 
			// IOCP fd
			int32 fd;
			// IOCP error code
			int32 ec;
			// Channel notifier 
			std::weak_ptr<void> ch_notifier;
			// Ref link count
			std::atomic_int link_cnt;

			union
			{
				// Client fd for accepting
				int32 client_fd;
				// IP address for connecting
				struct
				{
					int8 addr[64];
					int32 addr_len;
				} ip;
			}un;

			iocp_task(): 
				type(IOCP_TASK_NONE),
				processed_size(0),
				fd(-1),
				ec(0),
				link_cnt(1)
			{
				memset(&ol, 0, sizeof(ol));
				memset(&un, 0, sizeof(un));
			}

			void add_link()
			{
				link_cnt.fetch_add(1);
			}

			void sub_link()
			{
				link_cnt.fetch_sub(1);
				if (link_cnt == 0)
				{
					__release_resource();
					delete this;
				}
			}

			void __release_resource()
			{
				if (type == IOCP_TASK_ACCEPT)
				{
					if (un.client_fd > 0)
						close(un.client_fd);
				}
			}
#endif
		};

		iocp_task_ptr new_iocp_task()
		{
#ifdef WIN32
			return new iocp_task;
#else
			return nullptr;
#endif
		}

		void reuse_iocp_task(iocp_task_ptr itask)
		{
#ifdef WIN32
			memset(&itask->ol, 0, sizeof(itask->ol));
#endif
		}

		void link_iocp_task(iocp_task_ptr itask)
		{
#ifdef WIN32
			assert(itask);
			itask->add_link();
#endif
		}

		void unlink_iocp_task(iocp_task_ptr itask)
		{
#ifdef WIN32
			assert(itask);
			itask->sub_link();
#endif
		}

		void set_iocp_task_type(iocp_task_ptr itask, uint32 task_type)
		{
#ifdef WIN32
			assert(itask);
			itask->type = task_type;
#endif
		}

		uint32 get_iocp_task_type(iocp_task_ptr itask)
		{
#ifdef WIN32
			assert(itask);
			return itask->type;
#endif
			return IOCP_TASK_NONE;
		}

		void set_iocp_task_fd(iocp_task_ptr itask, int32 fd)
		{
#ifdef WIN32
			assert(itask);
			itask->fd = fd;
#endif
		}

		int32 get_iocp_task_fd(iocp_task_ptr itask)
		{
#ifdef WIN32
			assert(itask);
			return itask->fd;
#endif
			return -1;
		}

		void set_iocp_task_client_fd(iocp_task_ptr itask, int32 client_fd)
		{
#ifdef WIN32
			assert(itask);
			itask->un.client_fd = client_fd;
#endif
		}

		int32 get_iocp_task_client_fd(iocp_task_ptr itask)
		{
#ifdef WIN32
			assert(itask);
			return itask->un.client_fd;
#endif
			return -1;
		}

		void set_iocp_task_notifier(iocp_task_ptr itask, void_wptr ch_notifier)
		{
#ifdef WIN32
			assert(itask);
			itask->ch_notifier = ch_notifier;
#endif
		}

		void_wptr get_iocp_task_notifier(iocp_task_ptr itask)
		{
#ifdef WIN32
			assert(itask);
			return itask->ch_notifier;
#endif
			return void_wptr();
		}

		void set_iocp_task_ec(iocp_task_ptr itask, int32 ec)
		{
#ifdef WIN32
			assert(itask);
			itask->ec = ec;
#endif
		}

		int32 get_iocp_task_ec(iocp_task_ptr itask)
		{
#ifdef WIN32
			assert(itask);
			return itask->ec;
#endif
			return -1;
		}

		void set_iocp_task_buffer(iocp_task_ptr itask, block_ptr b, uint32 size)
		{
#ifdef WIN32
			assert(itask);
			itask->buf.buf = b;
			itask->buf.len = size;
#endif
		}

		void set_iocp_task_processed_size(iocp_task_ptr itask, int32 size)
		{
#ifdef WIN32
			assert(itask);
			itask->processed_size = size;
#endif
		}

		int32 get_iocp_task_processed_size(iocp_task_ptr itask)
		{
#ifdef WIN32
			assert(itask);
			return itask->processed_size;
#else
			return 0;
#endif
		}

		block_ptr get_iocp_task_processed_buffer(iocp_task_ptr itask)
		{
#ifdef WIN32
			assert(itask);
			return itask->buf.buf;
#else
			return nullptr;
#endif
		}

		sockaddr* get_iocp_task_remote_address(iocp_task_ptr itask, int32_ptr addrlen)
		{
#ifdef WIN32
			assert(itask);
			*addrlen = itask->un.ip.addr_len;
			return (sockaddr*)itask->un.ip.addr;
#else
			return nullptr;
#endif
		}

		int32 create_iocp_socket(int32 domain, int32 type, iocp_handler iocp)
		{
#ifdef WIN32
			int32 fd = (int32)::WSASocket(domain, type, IPPROTO_IP, NULL, 0, WSA_FLAG_OVERLAPPED);
			if (fd == -1 || CreateIoCompletionPort((HANDLE)fd, iocp, 0, 0) == NULL)
			{
				if (fd > 0)
					close(fd);
				return -1;
			}
			return fd;
#else
			return -1;
#endif
		}

		bool post_iocp_accept(net_extension_ptr ext, iocp_task_ptr itask)
		{
#ifdef WIN32
			assert(ext);
			assert(itask);

			LPFN_ACCEPTEX accept_ex = (LPFN_ACCEPTEX)get_accpet_ex_func(ext);
			if (!accept_ex)
				return false;

			DWORD bytes = 0;
			DWORD addrlen = sizeof(sockaddr_in) + 16;
			if (accept_ex(itask->fd, itask->un.client_fd, itask->buf.buf, 0, addrlen, addrlen, &bytes, &(itask->ol)) == FALSE)
				return false;

			return true;
#else
			return false;
#endif
		}

		bool get_iocp_accepted_address(
			net_extension_ptr ext,
			iocp_task_ptr itask,
			sockaddr **local,
			int32_ptr llen,
			sockaddr **remote,
			int32_ptr rlen
		) {
#ifdef WIN32
			assert(ext);
			assert(itask);

			LPFN_GETACCEPTEXSOCKADDRS get_addrs = (LPFN_GETACCEPTEXSOCKADDRS)get_accepted_addrs_func(ext);
			if (!get_addrs)
				return false;

			HANDLE fd = (HANDLE)itask->fd;
			DWORD addrlen = sizeof(sockaddr_in) + 16;
			get_addrs(itask->buf.buf, 0, addrlen, addrlen, local, llen, remote, rlen);
			if (setsockopt(itask->un.client_fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char*)&fd, sizeof(fd)) == SOCKET_ERROR)
				return false;

			return true;
#else
			return false;
#endif
		}

		bool post_iocp_connect(
			net_extension_ptr ext,
			iocp_task_ptr itask,
			const sockaddr *addr,
			int32 addrlen
		) {
#ifdef WIN32
			assert(ext);
			assert(itask);

			LPFN_CONNECTEX connect_ex = (LPFN_CONNECTEX)get_connect_ex_func(ext);
			if (!connect_ex)
				return false;

			if (connect_ex(itask->fd, addr, addrlen, NULL, 0, NULL, &(itask->ol)) == FALSE)
				return false;

			setsockopt(itask->fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);

			return true;
#else
			return false;
#endif
		}

		bool post_iocp_read(iocp_task_ptr itask)
		{
#ifdef WIN32
			assert(itask);

			DWORD bytes = 0, flags = 0;
			if (::WSARecv(itask->fd, &itask->buf, 1, &bytes, &flags, &(itask->ol), NULL) == SOCKET_ERROR)
			{
				int32 ec = net::last_errno();
				if (ec != WSA_IO_PENDING)
					return false;
			}

			return true;
#else
			return false;
#endif
		}

		bool post_iocp_read_from(iocp_task_ptr itask)
		{
#ifdef WIN32
			assert(itask);

			DWORD bytes = 0, flags = 0;
			itask->un.ip.addr_len = sizeof(itask->un.ip.addr);
			int32 ret = ::WSARecvFrom(itask->fd, &itask->buf, 1, &bytes, &flags, (sockaddr*)itask->un.ip.addr, &itask->un.ip.addr_len, &itask->ol, NULL);
			if (ret == SOCKET_ERROR)
			{
				int32 ec = net::last_errno();
				if (ec != WSA_IO_PENDING)
					return false;
			}
			return true;
#else
			return false;
#endif
		}

		bool post_iocp_write(iocp_task_ptr itask)
		{
#ifdef WIN32
			assert(itask);

			DWORD bytes;
			int32 ret = WSASend(itask->fd, &itask->buf, 1, &bytes, 0, (WSAOVERLAPPED*)&itask->ol, NULL);
			if (ret == SOCKET_ERROR)
			{
				int32 ec = net::last_errno();
				if (ec != WSA_IO_PENDING)
					return false;
			}

			return true;
#else
			return false;
#endif
		}

	}
}