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

#ifndef pump_net_iocp_h
#define pump_net_iocp_h

#include "pump/deps.h"
#include "pump/net/extension.h"

namespace pump {
	namespace net {

		#define IOCP_TASK_NONE    -1
		#define IOCP_TASK_SEND    0
		#define IOCP_TASK_READ    1
		#define	IOCP_TASK_CONNECT 2
		#define	IOCP_TASK_ACCEPT  3
		#define	IOCP_TASK_CHANNEL 4
		#define	IOCP_TASK_TRACKER 5

		struct iocp_task;
		DEFINE_RAW_POINTER_TYPE(iocp_task);

		typedef void_ptr iocp_handler;

		/*********************************************************************************
		 * Get iocp handler
		 ********************************************************************************/
		iocp_handler get_iocp_handler();

		/*********************************************************************************
		 * Create an iocp task with a link
		 ********************************************************************************/
		iocp_task_ptr new_iocp_task();

		/*********************************************************************************
		 * Reuse iocp task
		 * this will reset iocp overlapped.
		 ********************************************************************************/
		void reuse_iocp_task(iocp_task_ptr itask);

		/*********************************************************************************
		 * Link iocp task
		 ********************************************************************************/
		void link_iocp_task(iocp_task_ptr itask);

		/*********************************************************************************
		 * Sub iocp task
		 ********************************************************************************/
		void unlink_iocp_task(iocp_task_ptr itask);

		/*********************************************************************************
		 * Set iocp task type
		 ********************************************************************************/
		void set_iocp_task_type(iocp_task_ptr itask, uint32 task_type);

		/*********************************************************************************
		 * Get iocp task type
		 ********************************************************************************/
		uint32 get_iocp_task_type(iocp_task_ptr itask);

		/*********************************************************************************
		 * Set iocp task fd
		 ********************************************************************************/
		void set_iocp_task_fd(iocp_task_ptr itask, int32 fd);

		/*********************************************************************************
		 * Get iocp task fd
		 ********************************************************************************/
		int32 get_iocp_task_fd(iocp_task_ptr itask);

		/*********************************************************************************
		 * Set iocp task client fd
		 ********************************************************************************/
		void set_iocp_task_client_fd(iocp_task_ptr itask, int32 client_fd);

		/*********************************************************************************
		 * Get iocp task client socket
		 ********************************************************************************/
		int32 get_iocp_task_client_fd(iocp_task_ptr itask);

		/*********************************************************************************
		 * Set iocp task notifier
		 ********************************************************************************/
		void set_iocp_task_notifier(iocp_task_ptr itask, void_wptr ch_notifier);

		/*********************************************************************************
		 * Get iocp task notify
		 ********************************************************************************/
		void_sptr get_iocp_task_notifier(iocp_task_ptr itask);

		/*********************************************************************************
		 * Set iocp task error code
		 ********************************************************************************/
		void set_iocp_task_ec(iocp_task_ptr itask, int32 ec);

		/*********************************************************************************
		 * Get iocp task error code
		 ********************************************************************************/
		int32 get_iocp_task_ec(iocp_task_ptr itask);

		/*********************************************************************************
		 * Set iocp task buffer
		 ********************************************************************************/
		void set_iocp_task_buffer(iocp_task_ptr itask, block_ptr b, int32 size);

		/*********************************************************************************
		 * Set iocp task processed size
		 ********************************************************************************/
		void set_iocp_task_processed_size(iocp_task_ptr itask, int32 size);

		/*********************************************************************************
		 * Get iocp task processed size
		 ********************************************************************************/
		int32 get_iocp_task_processed_size(iocp_task_ptr itask);

		/*********************************************************************************
		 * Get iocp task processed data
		 ********************************************************************************/
		block_ptr get_iocp_task_processed_data(iocp_task_ptr itask, int32_ptr size);

		/*********************************************************************************
		 * Get iocp task remote address for udp reading from
		 ********************************************************************************/
		sockaddr* get_iocp_task_remote_address(iocp_task_ptr itask, int32_ptr addrlen);

		/*********************************************************************************
		 * Create iocp socket
		 ********************************************************************************/
		int32 create_iocp_socket(int32 domain, int32 type, iocp_handler iocp);

		/*********************************************************************************
		 * Post iocp accept
		 ********************************************************************************/
		bool post_iocp_accept(net_extension_ptr ext, iocp_task_ptr itask);

		/*********************************************************************************
		 * Get iocp accepted address
		 ********************************************************************************/
		bool get_iocp_accepted_address(
			net_extension_ptr ext,
			iocp_task_ptr itask,
			sockaddr **local,
			int32_ptr llen,
			sockaddr **remote,
			int32_ptr rlen
		);

		/*********************************************************************************
		 * Post iocp connect
		 ********************************************************************************/
		bool post_iocp_connect(
			net_extension_ptr ext,
			iocp_task_ptr itask,
			const sockaddr *addr,
			int32 addrlen
		);

		/*********************************************************************************
		 * Post iocp read
		 ********************************************************************************/
		bool post_iocp_read(iocp_task_ptr itask);

		/*********************************************************************************
		 * Post iocp read from
		 ********************************************************************************/
		bool post_iocp_read_from(iocp_task_ptr itask);

		/*********************************************************************************
		 * Post iocp send
		 ********************************************************************************/
		bool post_iocp_send(iocp_task_ptr itask);

		/*********************************************************************************
		 * Cancel posted iocp task
		 ********************************************************************************/
		void cancel_iocp_task(iocp_handler iocp, iocp_task_ptr itask);
	}
}

#endif