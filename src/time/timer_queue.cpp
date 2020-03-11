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

#include "pump/time/timer_queue.h"

namespace pump {
	namespace time {

		const int32 TIMER_DEFAULT_INTERVAL = 1000;

		timer_queue::timer_queue() :
			started_(false),
			next_observe_time_(0)
		{
		}

		timer_queue::~timer_queue()
		{
		}

		bool timer_queue::start(const timer_pending_callback &cb)
		{
			if (!started_)
			{
				started_ = true;

				pending_cb_ = cb;

				next_observe_time_ = get_clock_milliseconds() + TIMER_DEFAULT_INTERVAL;

				observer_.reset(new std::thread(
					function::bind(&timer_queue::__observe_thread, this)
				));
			}

			return started_;
		}

		bool timer_queue::stop()
		{
			if (started_)
			{
				started_ = false;

				observer_cv_.notify_all();

				if (observer_)
					observer_->join();
			}

			return true;
		}

		void timer_queue::add_timer(timer_sptr &ptr)
		{
			std::unique_lock<std::mutex> locker(observer_mx_);

			timers_.insert(std::make_pair(ptr->time(), ptr));
			if (next_observe_time_ > ptr->time())
			{
				next_observe_time_ = timers_.begin()->first;
				observer_cv_.notify_all();
			}
		}

		void timer_queue::delete_timer(timer_sptr &ptr)
		{
			std::unique_lock<std::mutex> locker(observer_mx_);

			uint64 key = ptr->time();
			auto beg = timers_.lower_bound(key);
			auto end = timers_.upper_bound(key);
			while (beg != end)
			{
				auto tmp = beg->second.lock();
				if (tmp && tmp.get() == ptr.get())
				{
					timers_.erase(beg);
					break;
				}
				++beg;
			}
		}

		void timer_queue::__observe_thread()
		{
			while (started_)
			{
				{
					std::unique_lock<std::mutex> locker(observer_mx_);

					uint64 now = get_clock_milliseconds();
					if (next_observe_time_ > now)
					{
						observer_cv_.wait_for(
							locker, std::chrono::milliseconds(next_observe_time_ - now)
						);
					}
				}

				if (started_)
					__observe();
			}
		}

		void timer_queue::__observe()
		{
			std::unique_lock<std::mutex> locker(observer_mx_);

			uint64 now = get_clock_milliseconds();
			next_observe_time_ = now + TIMER_DEFAULT_INTERVAL;

			auto it = timers_.begin();
			for (; it != timers_.end(); it++)
			{
				if (now < it->first)
				{
					next_observe_time_ = it->first;
					break;
				}

				pending_cb_(it->second);
			}

			timers_.erase(timers_.begin(), it);
		}

	}
}
