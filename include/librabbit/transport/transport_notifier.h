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

#ifndef librabbit_transport_notify_h
#define librabbit_transport_notify_h

#include "librabbit/deps.h"
#include "librabbit/transport/address.h"
#include "librabbit/transport/transport_base.h"

namespace librabbit {
	namespace transport {

		class LIB_EXPORT accepted_notifier
		{
		public:
			/*********************************************************************************
			 * Accepted event callback
			 ********************************************************************************/
			virtual void on_accepted_callback(void_ptr ctx, transport_base_sptr transp) = 0;

			/*********************************************************************************
			 * Stopped accepting event callback
			 ********************************************************************************/
			virtual void on_stopped_accepting_callback(void_ptr ctx) = 0;
		};
		DEFINE_ALL_POINTER_TYPE(accepted_notifier);

		class LIB_EXPORT dialed_notifier
		{
		public:
			/*********************************************************************************
			 * Dialed event callback
			 ********************************************************************************/
			virtual void on_dialed_callback(void_ptr ctx, transport_base_sptr transp, bool succ) = 0;

			/*********************************************************************************
			 * Dialed timeout event callback
			 ********************************************************************************/
			virtual void on_dialed_timeout_callback(void_ptr ctx) = 0;

			/*********************************************************************************
			 * Stopped dial event callback
			 ********************************************************************************/
			virtual void on_stopped_dialing_callback(void_ptr ctx) = 0;
		};
		DEFINE_ALL_POINTER_TYPE(dialed_notifier);

		class LIB_EXPORT transport_io_notifier
		{
		public:
			/*********************************************************************************
			 * Recv event callback
			 ********************************************************************************/
			virtual void on_recv_callback(transport_base_ptr transp, c_block_ptr b, int32 size) = 0;

			/*********************************************************************************
			 * Sent event callback
			 ********************************************************************************/
			virtual void on_sent_callback(transport_base_ptr transp) = 0;
		};
		DEFINE_ALL_POINTER_TYPE(transport_io_notifier);

		class LIB_EXPORT transport_terminated_notifier
		{
		public:
			/*********************************************************************************
			 * Disconnected event callback
			 ********************************************************************************/
			virtual void on_disconnected_callback(transport_base_ptr transp) = 0;

			/*********************************************************************************
			 * Stopped event callback
			 ********************************************************************************/
			virtual void on_stopped_callback(transport_base_ptr transp) = 0;
		};
		DEFINE_ALL_POINTER_TYPE(transport_terminated_notifier);

		class LIB_EXPORT transport_udp_notifier
		{
		public:
			/*********************************************************************************
			 * Read event callback for udp
			 ********************************************************************************/
			virtual void on_recv_callback(transport_base_ptr transp, c_block_ptr b, int32 size, const address &remote_address) = 0;

			/*********************************************************************************
			 * Stopped event callback
			 ********************************************************************************/
			virtual void on_stopped_callback(transport_base_ptr transp) = 0;
		};
		DEFINE_ALL_POINTER_TYPE(transport_udp_notifier);

	}
}

#endif