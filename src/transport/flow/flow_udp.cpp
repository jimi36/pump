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

#include "pump/transport/flow/flow_udp.h"

namespace pump {
	namespace transport {
		namespace flow {

			#define UDP_BUFFER_SIZE 1024*64

			flow_udp::flow_udp() PUMP_NOEXCEPT : 
				read_task_(nullptr)
			{
			}

			flow_udp::~flow_udp()
			{
#if defined(WIN32) && defined(USE_IOCP)
				if (read_task_)
					net::unlink_iocp_task(read_task_);
#endif
			}

			int32 flow_udp::init(poll::channel_sptr &ch, PUMP_CONST address &local_address)
			{
				PUMP_ASSERT_EXPR(ch, ch_ = ch);
		
				int32 domain = AF_INET;
				if (local_address.is_ipv6())
					domain = AF_INET6;

#if defined(WIN32) && defined(USE_IOCP)
				fd_ = net::create_iocp_socket(domain, SOCK_DGRAM, net::get_iocp_handler());
#else
				fd_ = net::create_socket(domain, SOCK_DGRAM);
#endif
				if (fd_ == -1)
					return FLOW_ERR_ABORT;

#if defined(WIN32) && defined(USE_IOCP)
				read_task_ = net::new_iocp_task();
				net::set_iocp_task_fd(read_task_, fd_);
				net::set_iocp_task_notifier(read_task_, ch_);
				net::set_iocp_task_type(read_task_, IOCP_TASK_READ);
				net::set_iocp_task_buffer(read_task_, (block_ptr)read_cache_.data(), (uint32)read_cache_.size());
#endif
				if (!net::set_reuse(fd_, 1) ||
					!net::set_noblock(fd_, 1) ||
					!net::bind(fd_, (sockaddr*)local_address.get(), local_address.len()) ||
					!net::set_udp_conn_reset(fd_, false))
					return FLOW_ERR_ABORT;

				read_cache_.resize(UDP_BUFFER_SIZE);

				return FLOW_ERR_NO;
			}

			int32 flow_udp::want_to_read()
			{
#if defined(WIN32) && defined(USE_IOCP)
				PUMP_ASSERT(read_task_);
				if (!net::post_iocp_read_from(read_task_))
					return FLOW_ERR_ABORT;
#endif
				return FLOW_ERR_NO;
			}

			c_block_ptr flow_udp::read_from(
				net::iocp_task_ptr itask, 
				int32_ptr size, 
				address_ptr remote_address
			) {
#if defined(WIN32) && defined(USE_IOCP)
				c_block_ptr buf = net::get_iocp_task_processed_data(itask, size);
				if (PUMP_LIKELY(*size > 0))
				{
					int32 addrlen = 0;
					sockaddr *addr = net::get_iocp_task_remote_address(itask, &addrlen);
					remote_address->set(addr, addrlen);
				}
#else
				block addr[ADDRESS_MAX_LEN];
				int32 addrlen = ADDRESS_MAX_LEN;
				block_ptr buf = (block_ptr)read_cache_.data();
				*size = net::read_from(fd_, buf, (uint32)read_cache_.size(), (sockaddr*)addr, &addrlen);

				remote_address->set((sockaddr*)addr, addrlen);
#endif
				return buf;
			}

			int32 flow_udp::send(c_block_ptr b, uint32 size, PUMP_CONST address &remote_address)
			{
				return net::send_to(fd_, b, size, (struct sockaddr*)remote_address.get(), remote_address.len());
			}

		}
	}
}