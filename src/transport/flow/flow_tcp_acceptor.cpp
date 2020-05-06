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

#include "pump/transport/flow/flow_tcp_acceptor.h"

namespace pump {
	namespace transport {
		namespace flow {

			flow_tcp_acceptor::flow_tcp_acceptor() PUMP_NOEXCEPT : 
				is_ipv6_(false),
				accept_task_(nullptr)
			{
			}

			flow_tcp_acceptor::~flow_tcp_acceptor()
			{
#if defined(WIN32) && defined(USE_IOCP)
				if (accept_task_)
					net::unlink_iocp_task(accept_task_);
#endif
			}

			int32 flow_tcp_acceptor::init(poll::channel_sptr &ch, PUMP_CONST address &listen_address)
			{
				PUMP_ASSERT_EXPR(ch, ch_ = ch);

				is_ipv6_ = listen_address.is_ipv6();
				int32 domain = is_ipv6_ ? AF_INET6 : AF_INET;

#if defined(WIN32) && defined(USE_IOCP)
				fd_ = net::create_iocp_socket(domain, SOCK_STREAM, net::get_iocp_handler());
				if (fd_ == -1)
					return FLOW_ERR_ABORT;

				ext_ = net::new_net_extension(fd_);
				if (!ext_)
					return FLOW_ERR_ABORT;

				tmp_cache_.resize(ADDRESS_MAX_LEN * 3);

				accept_task_ = net::new_iocp_task();
				net::set_iocp_task_fd(accept_task_, fd_);
				net::set_iocp_task_notifier(accept_task_, ch_);
				net::set_iocp_task_type(accept_task_, IOCP_TASK_ACCEPT);
				net::set_iocp_task_buffer(accept_task_, (block_ptr)tmp_cache_.data(), (uint32)tmp_cache_.size());
#else
				fd_ = net::create_socket(domain, SOCK_STREAM);
				if (fd_ == -1)
					return FLOW_ERR_ABORT;
#endif
				if (!net::set_reuse(fd_, 1) ||
					!net::set_noblock(fd_, 1) ||
					!net::set_nodelay(fd_, 1) ||
					!net::bind(fd_, (sockaddr*)listen_address.get(), listen_address.len()) ||
					!net::listen(fd_))
					return FLOW_ERR_ABORT;

				return FLOW_ERR_NO;
			}

			int32 flow_tcp_acceptor::want_to_accept()
			{
#if defined(WIN32) && defined (USE_IOCP)
				int32 domain = is_ipv6_ ? AF_INET6 : AF_INET;
				int32 client = net::create_iocp_socket(domain, SOCK_STREAM, net::get_iocp_handler());
				if (client == -1)
					return FLOW_ERR_ABORT;

				net::set_iocp_task_client_fd(accept_task_, client);
				if (!net::post_iocp_accept(ext_, accept_task_))
				{
					net::close(client);
					return FLOW_ERR_ABORT;
				}
#endif
				return FLOW_ERR_NO;
			}

			int32 flow_tcp_acceptor::accept(
				net::iocp_task_ptr itask, 
				address_ptr local_address, 
				address_ptr remote_address
			) {
#if defined(WIN32) && defined(USE_IOCP)
				int32 ec = net::get_iocp_task_ec(itask);
				int32 client_fd = net::get_iocp_task_client_fd(itask);
				if (ec != 0 || client_fd == -1)
				{
					net::close(client_fd);
					return -1;
				}

				sockaddr *local = nullptr;
				sockaddr *remote = nullptr;
				int32 llen = sizeof(sockaddr_in);
				int32 rlen = sizeof(sockaddr_in);
				if (!net::get_iocp_accepted_address(ext_, itask, &local, &llen, &remote, &rlen))
				{
					net::close(client_fd);
					return -1;
				}
				local_address->set(local, llen);
				remote_address->set(remote, rlen);

				net::set_iocp_task_client_fd(itask, 0);
#else
				int32 addrlen = ADDRESS_MAX_LEN;
				int32 client_fd = net::accept(fd_, (struct sockaddr*)tmp_cache_.data(), &addrlen);
				if (client_fd == -1)
					return -1;
				remote_address->set((sockaddr*)tmp_cache_.data(), addrlen);

				addrlen = ADDRESS_MAX_LEN;
				net::local_address(client_fd, (sockaddr*)tmp_cache_.data(), &addrlen);
				local_address->set((sockaddr*)tmp_cache_.data(), addrlen);
#endif
				if (!net::set_noblock(client_fd, 1) ||
					!net::set_nodelay(client_fd, 1))
				{
					net::close(client_fd);
					return -1;
				}

				return client_fd;
			}

		}
	}
}