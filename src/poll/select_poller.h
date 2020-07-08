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

#ifndef pump_poll_select_poller_h
#define pump_poll_select_poller_h

#include "pump/poll/poller.h"

namespace pump {
	namespace poll {

		class select_poller : 
			public poller
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			select_poller(bool pop_pending) noexcept;

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~select_poller() = default;

		protected:
			/*********************************************************************************
			 * Poll
			 ********************************************************************************/
			virtual void __poll(int32 timeout) override;

		private:
			/*********************************************************************************
			 * Dispatch pending event
			 ********************************************************************************/
			void __dispatch_pending_event(const fd_set *rfds, const fd_set *wfds);

		private:
			fd_set rfds_;
			fd_set wfds_;

			struct timeval tv_;
		};

	}
}

#endif
