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

#include "pump/time/timer.h"
#include "pump/time/timer_queue.h"

namespace pump {
	namespace time {

		const int32 TIMER_STOPPED  = 0;
		const int32 TIMER_STARTING = 1;
		const int32 TIMER_PENDING  = 2;

		timer::timer(
			const timer_callback &cb,
			uint64 interval, 
			bool repeated
		): 
			status_(TIMER_STOPPED),
			cb_(cb),
			repeated_(repeated),
			interval_(interval),
			overtime_(0)
		{
		}

		bool timer::__start() 
		{
			if (!__set_status(TIMER_STOPPED, TIMER_STARTING))
				return false;

			overtime_ = get_clock_milliseconds() + interval_;

			return true;
		}

		void timer::stop()
		{
			repeated_ = false;

			while (true)
			{
				if (__set_status(TIMER_STOPPED, TIMER_STOPPED))
					break;
				else if (__set_status(TIMER_STARTING, TIMER_STOPPED))
					break;
				else if (__set_status(TIMER_PENDING, TIMER_STOPPED))
					break;
			}
		}

		void timer::handle_timeout(void_ptr tq)
		{
			if (!__set_status(TIMER_STARTING, TIMER_STOPPED))
				return;

			if (cb_)
				cb_();

			if (repeated_)
				((timer_queue_ptr)tq)->add_timer(shared_from_this());
		}

	}
}