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

namespace pump {
	namespace time {

		const int32 TIMER_STOPPED  = 0;
		const int32 TIMER_STARTING = 1;
		const int32 TIMER_PENDING  = 2;

		timer::timer(void_ptr arg, timeout_notifier_sptr &notifier, uint64 interval, bool repeat): 
			arg_(arg),
			status_(TIMER_STOPPED),
			repeated_(repeat),
			interval_(interval),
			overtime_(0),
			notifier_(notifier)
		{
		}

		bool timer::start() 
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

			notifier_.reset();
		}

		void timer::handle_timeout()
		{
			if (!__set_status(TIMER_STARTING, TIMER_STOPPED))
				return;

			auto notify = notifier_.lock();
			if (notify)
				notify->on_timer_timeout(arg_);
		}

	}
}