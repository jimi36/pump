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

#include "pump/transport/flow/flow_tcp.h"

namespace pump {
	namespace transport {
		namespace flow {

			flow_tcp::flow_tcp():
				recv_task_(nullptr),
				send_task_(nullptr),
				send_buffer_(nullptr)
			{
			}

			flow_tcp::~flow_tcp()
			{
				if (recv_task_)
					net::unlink_iocp_task(recv_task_);
				if (send_task_)
					net::unlink_iocp_task(send_task_);
			}

			int32 flow_tcp::init(poll::channel_sptr &ch, int32 fd)
			{
				if (fd <= 0 || !ch)
					return FLOW_ERR_ABORT;

				ch_ = ch;
				fd_ = fd;

				recv_cache_.resize(MAX_FLOW_BUFFER_SIZE);
				recv_task_ = net::new_iocp_task();
				net::set_iocp_task_fd(recv_task_, fd_);
				net::set_iocp_task_notifier(recv_task_, ch_);
				net::set_iocp_task_type(recv_task_, IOCP_TASK_RECV);
				net::set_iocp_task_buffer(recv_task_, (block_ptr)recv_cache_.data(), (uint32)recv_cache_.size());

				send_task_ = net::new_iocp_task();
				net::set_iocp_task_fd(send_task_, fd_);
				net::set_iocp_task_notifier(send_task_, ch_);
				net::set_iocp_task_type(send_task_, IOCP_TASK_SEND);

				return FLOW_ERR_NO;
			}

			int32 flow_tcp::want_to_recv()
			{
#if defined(WIN32) && defined(USE_IOCP)
				net::link_iocp_task(recv_task_);
				net::reuse_iocp_task(recv_task_);
				if (!net::post_iocp_read(recv_task_))
				{
					net::unlink_iocp_task(recv_task_);
					return FLOW_ERR_ABORT;
				}
#endif
				return FLOW_ERR_NO;
			}

			c_block_ptr flow_tcp::recv(net::iocp_task_ptr itask, int32_ptr size)
			{
#if defined(WIN32) && defined(USE_IOCP)
				assert(recv_task_ == itask);
				*size = net::get_iocp_task_processed_size(itask);
				c_block_ptr b = net::get_iocp_task_processed_buffer(itask);
				net::unlink_iocp_task(itask);
#else
				block_ptr b = (block_ptr)recv_cache_.data();
				*size = net::recv(fd_, b, (uint32)recv_cache_.size());
				if (*size < 0)
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
#endif
				return b;
			}

			int32 flow_tcp::want_to_send(buffer_ptr wb)
			{
				send_buffer_ = wb;

#if defined(WIN32) && defined(USE_IOCP)
				net::link_iocp_task(send_task_);
				net::reuse_iocp_task(send_task_);
				net::set_iocp_task_buffer(send_task_, (block_ptr)send_buffer_->data(), send_buffer_->data_size());
				if (!net::post_iocp_write(send_task_))
				{
					net::unlink_iocp_task(send_task_);
					return FLOW_ERR_ABORT;
				}
				return FLOW_ERR_AGAIN;
#else
				int32 size = net::send(get_fd(), send_buffer_->data(), send_buffer_->data_size());
				if (size <= 0)
				{
					switch (net::last_errno())
					{
					case LANE_EINPROGRESS:
					case LANE_EWOULDBLOCK:
						return FLOW_ERR_AGAIN;
					default:
						return FLOW_ERR_ABORT;
					}
				}

				if (!send_buffer_->shift(size))
					assert(false);

				return FLOW_ERR_AGAIN;
#endif
			}

			int32 flow_tcp::send(net::iocp_task_ptr itask)
			{
#if defined(WIN32) && defined(USE_IOCP)
				assert(send_task_ == itask);
				int32 size = net::get_iocp_task_processed_size(itask);
				net::unlink_iocp_task(itask);
				if (size < 0)
					return FLOW_ERR_ABORT;
#else
				if (!has_data_to_send())
					return FLOW_ERR_NO_DATA;

				int32 size = net::send(get_fd(), send_buffer_->data(), send_buffer_->data_size());
				if (size <= 0)
				{
					switch (net::last_errno())
					{
					case LANE_EINPROGRESS:
					case LANE_EWOULDBLOCK:
						return FLOW_ERR_AGAIN;
					default:
						return FLOW_ERR_ABORT;
					}
				}
#endif
				if (!send_buffer_->shift(size))
					assert(false);

				if (send_buffer_->data_size() == 0)
					return FLOW_ERR_NO_DATA;
		
				return FLOW_ERR_AGAIN;
			}

		}
	}
}