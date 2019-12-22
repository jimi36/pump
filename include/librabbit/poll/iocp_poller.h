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

#ifndef librabbit_poll_iocp_poller_h
#define librabbit_poll_iocp_poller_h

#include "librabbit/net/iocp.h"
#include "librabbit/poll/poller.h"

namespace librabbit {
	namespace poll {

		class iocp_poller: public poller
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			iocp_poller(bool pop_pending);

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~iocp_poller();

			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			virtual bool start();

			/*********************************************************************************
			 * Stop
			 ********************************************************************************/
			virtual void stop();

			/*********************************************************************************
			 * Wait stopping
			 ********************************************************************************/
			virtual void wait_stop();

			/*********************************************************************************
			 * Add channel tracker
			 ********************************************************************************/
			virtual void add_channel_tracker(channel_tracker_sptr &tracker);

			/*********************************************************************************
			 * Remove channel tracker
			 ********************************************************************************/
			virtual void remove_channel_tracker(channel_tracker_sptr &tracker);

			/*********************************************************************************
			 * Awake channel tracker
			 ********************************************************************************/
			virtual void awake_channel_tracker(channel_tracker_sptr &tracker) {}

			/*********************************************************************************
			 * Push channel event
			 ********************************************************************************/
			virtual void push_channel_event(channel_sptr &c, uint32 event);

			/*********************************************************************************
			 * Get iocp handler
			 ********************************************************************************/
			net::iocp_handler get_iocp_handler() const { return iocp_; }

		protected:
			/*********************************************************************************
			 * Work thread
			 ********************************************************************************/
			void __work_thread();

		private:
			// iocp hanler
			net::iocp_handler iocp_;

			std::vector<std::thread*> workrs_;
		};

		DEFINE_ALL_POINTER_TYPE(iocp_poller);

	}
}

#endif