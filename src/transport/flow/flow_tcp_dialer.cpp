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

#include "librabbit/transport/flow/flow_tcp_dialer.h"

namespace librabbit {
	namespace transport {
		namespace flow {

			flow_tcp_dialer::flow_tcp_dialer(): 
				is_ipv6_(false)
			{
			}

			flow_tcp_dialer::~flow_tcp_dialer()
			{
			}

			int32 flow_tcp_dialer::init(poll::channel_sptr &ch, net::iocp_handler iocp, const address &bind_address)
			{
				if (!ch)
					return FLOW_ERR_ABORT;

				ch_ = ch;

				is_ipv6_ = bind_address.is_ipv6();
				int32 domain = is_ipv6_ ? AF_INET6 : AF_INET;

#if defined(WIN32) && defined(USE_IOCP)
				fd_ = net::create_iocp_socket(domain, SOCK_STREAM, iocp);
				if (fd_ == -1)
					return FLOW_ERR_ABORT;

				ext_ = net::new_net_extension(fd_);
				if (!ext_)
					return FLOW_ERR_ABORT;
#else
				if ((fd_ = net::create_socket(domain, SOCK_STREAM)) == -1)
					return FLOW_ERR_ABORT;
#endif
				if (!net::set_reuse(fd_, 1) ||
					!net::set_noblock(fd_, 1) ||
					!net::set_keeplive(fd_, 3, 3) ||
					!net::bind(fd_, (sockaddr*)bind_address.get(), bind_address.len()))
					return FLOW_ERR_ABORT;

				return FLOW_ERR_NO;
			}

			int32 flow_tcp_dialer::want_to_connect(const address &connect_address)
			{
#if defined(WIN32) && defined(USE_IOCP)
				auto itask = net::new_iocp_task();
				net::set_iocp_task_fd(itask, fd_);
				net::set_iocp_task_notifier(itask, ch_);
				net::set_iocp_task_type(itask, IOCP_TASK_CONNECT);
				if (!net::post_iocp_connect(ext_, itask, connect_address.get(), connect_address.len()))
				{
					int32 ec = net::last_errno();
					if (ec != WSA_IO_PENDING)
					{
						net::unlink_iocp_task(itask);
						return FLOW_ERR_ABORT;
					}
				}
#else
				if (!net::connect(fd_, (sockaddr*)connect_address.get(), connect_address.len()))
				{
					int32 ec = net::last_errno();
					if (ec != LANE_EALREADY &&
						ec != LANE_EWOULDBLOCK &&
						ec != LANE_EINPROGRESS)
						return FLOW_ERR_ABORT;
				}
#endif
				return FLOW_ERR_NO;
			}

			int32 flow_tcp_dialer::connect(net::iocp_task_ptr itask, address &local_address, address &remote_address)
			{
#if defined(WIN32) && defined(USE_IOCP)
				int32 ec = net::get_iocp_task_ec(itask);
				net::unlink_iocp_task(itask);
#else
				int32 ec = net::get_socket_error(fd_);
#endif
				if (ec != 0)
					return ec;

				if (!net::update_connect_context(fd_))
				{
					ec = net::get_socket_error(fd_);
					return ec;
				}

				int32 addrlen = 0;
				int8 addr[ADDRESS_MAX_LEN];

				addrlen = ADDRESS_MAX_LEN;
				net::local_address(fd_, (sockaddr*)addr, &addrlen);
				local_address.set((sockaddr*)addr, addrlen);

				addrlen = ADDRESS_MAX_LEN;
				net::remote_address(fd_, (sockaddr*)addr, &addrlen);
				remote_address.set((sockaddr*)addr, addrlen);

				return ec;
			}

		}
	}
}