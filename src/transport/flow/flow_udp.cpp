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

#include "librabbit/transport/flow/flow_udp.h"

namespace librabbit {
	namespace transport {
		namespace flow {

#define UDP_BUFFER_SIZE 1024*64

			flow_udp::flow_udp():
				recv_task_(nullptr)
			{
			}

			flow_udp::~flow_udp()
			{
				if (recv_task_)
					net::unlink_iocp_task(recv_task_);
			}

			int32 flow_udp::init(poll::channel_sptr &ch, net::iocp_handler iocp, const address &bind_address)
			{
				if (!ch)
					return FLOW_ERR_ABORT;

				ch_ = ch;

				int32 domain = AF_INET;
				if (bind_address.is_ipv6())
					domain = AF_INET6;

#if defined(WIN32) && defined(USE_IOCP)
				fd_ = net::create_iocp_socket(domain, SOCK_DGRAM, iocp);
#else
				fd_ = net::create_socket(domain, SOCK_DGRAM);
#endif
				if (fd_ == -1)
					return FLOW_ERR_ABORT;

#if defined(WIN32) && defined(USE_IOCP)
				recv_task_ = net::new_iocp_task();
				net::set_iocp_task_fd(recv_task_, fd_);
				net::set_iocp_task_notifier(recv_task_, ch_);
				net::set_iocp_task_type(recv_task_, IOCP_TASK_RECV);
				net::set_iocp_task_buffer(recv_task_, (block_ptr)recv_cache_.data(), (uint32)recv_cache_.size());
#endif
				if (!net::set_reuse(fd_, 1) ||
					!net::set_noblock(fd_, 1) ||
					!net::bind(fd_, (sockaddr*)bind_address.get(), bind_address.len()) ||
					!net::set_udp_conn_reset(fd_, false))
					return FLOW_ERR_ABORT;

				recv_cache_.resize(UDP_BUFFER_SIZE);

				return FLOW_ERR_NO;
			}

			int32 flow_udp::want_to_recv()
			{
#if defined(WIN32) && defined(USE_IOCP)
				net::link_iocp_task(recv_task_);
				net::reuse_iocp_task(recv_task_);
				if (!net::post_iocp_read_from(recv_task_))
				{
					net::unlink_iocp_task(recv_task_);
					return FLOW_ERR_ABORT;
				}
#endif
				return FLOW_ERR_NO;
			}

			c_block_ptr flow_udp::recv_from(net::iocp_task_ptr itask, int32_ptr size, address_ptr remote_address)
			{
#if defined(WIN32) && defined(USE_IOCP)
				assert(recv_task_ == itask);
				*size = net::get_iocp_task_processed_size(itask);
				c_block_ptr buf = net::get_iocp_task_processed_buffer(itask);
				if (*size > 0)
				{
					int32 addrlen = 0;
					sockaddr *addr = net::get_iocp_task_remote_address(itask, &addrlen);
					remote_address->set(addr, addrlen);
				}
				net::unlink_iocp_task(itask);
#else
				int8 addr[ADDRESS_MAX_LEN];
				int32 addrlen = ADDRESS_MAX_LEN;
				block_ptr buf = (block_ptr)recv_cache_.data();
				*size = net::read_from(fd_, buf, (uint32)recv_cache_.size(), (sockaddr*)addr, &addrlen);
				if (size < 0)
				{
					switch (net::last_errno())
					{
					case LANE_EINPROGRESS:
					case LANE_EWOULDBLOCK:
						*size = -1;
						break;
					default:
						*size = 0;
						break;
					}
				}

				remote_address->set((sockaddr*)addr, addrlen);
#endif
				return buf;
			}

			int32 flow_udp::send_to(c_block_ptr b, uint32 size, const address &remote_addr)
			{
				int32 wsize = net::write_to(fd_, b, size, (struct sockaddr*)remote_addr.get(), remote_addr.len());
				if (wsize < 0)
				{
					switch (net::last_errno())
					{
					case LANE_EINPROGRESS:
					case LANE_EWOULDBLOCK:
						wsize = -1;
						break;
					default:
						wsize = 0;
						break;
					}
				}
				return wsize;
			}

		}
	}
}