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

#include "extra.h"

namespace pump {
	namespace net {

		#define IOCP_TASK_NONE    -1
		#define IOCP_TASK_SEND    0
		#define IOCP_TASK_READ    1
		#define	IOCP_TASK_CONNECT 2
		#define	IOCP_TASK_ACCEPT  3
		#define	IOCP_TASK_CHANNEL 4
		#define	IOCP_TASK_TRACKER 5

		typedef void_ptr iocp_handler;

		/*********************************************************************************
		 * Get iocp handler
		 ********************************************************************************/
		iocp_handler get_iocp_handler();

		/*********************************************************************************
		 * Create an iocp task with a link
		 ********************************************************************************/
		void_ptr new_iocp_task();

		/*********************************************************************************
		 * Reuse iocp task
		 * this will reset iocp overlapped.
		 ********************************************************************************/
		void reuse_iocp_task(void_ptr task);

		/*********************************************************************************
		 * Link iocp task
		 ********************************************************************************/
		void link_iocp_task(void_ptr task);

		/*********************************************************************************
		 * Sub iocp task
		 ********************************************************************************/
		void unlink_iocp_task(void_ptr task);

		/*********************************************************************************
		 * Set iocp task type
		 ********************************************************************************/
		void set_iocp_task_type(void_ptr task, uint32 task_type);

		/*********************************************************************************
		 * Get iocp task type
		 ********************************************************************************/
		uint32 get_iocp_task_type(void_ptr task);

		/*********************************************************************************
		 * Set iocp task fd
		 ********************************************************************************/
		void set_iocp_task_fd(void_ptr task, int32 fd);

		/*********************************************************************************
		 * Get iocp task fd
		 ********************************************************************************/
		int32 get_iocp_task_fd(void_ptr task);

		/*********************************************************************************
		 * Set iocp task client fd
		 ********************************************************************************/
		void set_iocp_task_client_fd(void_ptr task, int32 client_fd);

		/*********************************************************************************
		 * Get iocp task client socket
		 ********************************************************************************/
		int32 get_iocp_task_client_fd(void_ptr task);

		/*********************************************************************************
		 * Set iocp task notifier
		 ********************************************************************************/
		void set_iocp_task_notifier(void_ptr task, void_wptr ch);

		/*********************************************************************************
		 * Get iocp task notify
		 ********************************************************************************/
		void_sptr get_iocp_task_notifier(void_ptr task);

		/*********************************************************************************
		 * Set iocp task error code
		 ********************************************************************************/
		void set_iocp_task_ec(void_ptr task, int32 ec);

		/*********************************************************************************
		 * Get iocp task error code
		 ********************************************************************************/
		int32 get_iocp_task_ec(void_ptr task);

		/*********************************************************************************
		 * Set iocp task buffer
		 ********************************************************************************/
		void set_iocp_task_buffer(void_ptr task, block_ptr b, int32 size);

		/*********************************************************************************
		 * Set iocp task processed size
		 ********************************************************************************/
		void set_iocp_task_processed_size(void_ptr task, int32 size);

		/*********************************************************************************
		 * Get iocp task processed size
		 ********************************************************************************/
		int32 get_iocp_task_processed_size(void_ptr task);

		/*********************************************************************************
		 * Get iocp task processed data
		 ********************************************************************************/
		block_ptr get_iocp_task_processed_data(void_ptr task, int32_ptr size);

		/*********************************************************************************
		 * Get iocp task remote address for udp reading from
		 ********************************************************************************/
		sockaddr* get_iocp_task_remote_address(void_ptr task, int32_ptr addrlen);

		/*********************************************************************************
		 * Create iocp socket
		 ********************************************************************************/
		int32 create_iocp_socket(int32 domain, int32 type, iocp_handler iocp);

		/*********************************************************************************
		 * Post iocp accept
		 ********************************************************************************/
		bool post_iocp_accept(void_ptr ex_fns, void_ptr task);

		/*********************************************************************************
		 * Get iocp accepted address
		 ********************************************************************************/
		bool get_iocp_accepted_address(
			void_ptr ex_fns,
			void_ptr task,
			sockaddr **local,
			int32_ptr llen,
			sockaddr **remote,
			int32_ptr rlen
		);

		/*********************************************************************************
		 * Post iocp connect
		 ********************************************************************************/
		bool post_iocp_connect(
			void_ptr ex_fns,
			void_ptr task,
			const sockaddr *addr,
			int32 addrlen
		);

		/*********************************************************************************
		 * Post iocp read
		 ********************************************************************************/
		bool post_iocp_read(void_ptr task);

		/*********************************************************************************
		 * Post iocp read from
		 ********************************************************************************/
		bool post_iocp_read_from(void_ptr task);

		/*********************************************************************************
		 * Post iocp send
		 ********************************************************************************/
		bool post_iocp_send(void_ptr task);

	}
}

#endif