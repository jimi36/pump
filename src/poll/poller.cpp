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

#include "pump/poll/poller.h"

namespace pump {
	namespace poll {

		poller::poller(bool pop_pending) PUMP_NOEXCEPT:
			started_(false),
			pop_pending_channel_(pop_pending),
			cev_cnt_(0),
			cevents_(1024),
			tev_cnt_(0),
			tevents_(1024)
		{
		}

		bool poller::start()
		{
			if (started_.load())
				return false;

			started_.store(true);

			worker_.reset(new std::thread([&]() {
				while (started_.load() || !trackers_.empty())
				{
					__handle_channel_events();

					__handle_channel_tracker_events();

					__poll(3);
				}
			}));

			return true;
		}

		void poller::wait_stopped()
		{
			if (worker_)
			{
				worker_->join();
				worker_.reset();
			}
		}

		bool poller::add_channel_tracker(channel_tracker_sptr &tracker, bool tracking)
		{
			if (started_.load())
			{
				tracker->__set_tracked(tracking);

				auto tev = new channel_tracker_event(tracker, TRACKER_EVENT_ADD);
				PUMP_DEBUG_CHECK(tevents_.enqueue(tev));
				tev_cnt_++;

				return true;
			}

			return false;
		}

		void poller::remove_channel_tracker(channel_tracker_sptr &tracker)
		{
			auto tev = new channel_tracker_event(tracker, TRACKER_EVENT_DEL);
			PUMP_DEBUG_CHECK(tevents_.enqueue(tev));
			tev_cnt_++;
		}

		void poller::pause_channel_tracker(channel_tracker_ptr tracker)
		{
			PUMP_ASSERT(tracker);
			tracker->__set_tracked(false);

			__pause_channel_tracker(tracker);
		}

		void poller::awake_channel_tracker(channel_tracker_ptr tracker)
		{
			PUMP_ASSERT(tracker);
			tracker->__set_tracked(true);

			__awake_channel_tracker(tracker);
		}

		void poller::push_channel_event(channel_sptr &c, uint32 event)
		{
			if (started_.load())
			{
				auto cev = new channel_event(c, event);
				PUMP_DEBUG_CHECK(cevents_.enqueue(cev));
				cev_cnt_++;
			}
		}

		void poller::__handle_channel_events()
		{
			channel_event_ptr ev = nullptr;
			auto cnt = cev_cnt_.exchange(0);
			while (cnt > 0 && cevents_.try_dequeue(ev))
			{
				PUMP_LOCK_WPOINTER(ch, ev->ch);
				if (ch)
					ch->handle_channel_event(ev->event);

				delete ev;

				cnt--;
			}
		}

		void poller::__handle_channel_tracker_events()
		{
			auto cnt = tev_cnt_.exchange(0);
			channel_tracker_event_ptr ev = nullptr;
			while (cnt > 0 && tevents_.try_dequeue(ev))
			{
				do 
				{
					auto tracker = ev->tracker.get();

					PUMP_LOCK_SPOINTER(ch, tracker->get_channel());
					if (ch == nullptr)
					{
						trackers_.erase(tracker);
						break;
					}

					if (ev->event == TRACKER_EVENT_ADD)
					{
						if (tracker->is_tracked())
							PUMP_DEBUG_CHECK(__add_channel_tracker(tracker));

						trackers_[tracker] = ev->tracker;
					}
					else if (ev->event == TRACKER_EVENT_DEL)
					{
						__remove_channel_tracker(tracker);
						trackers_.erase(tracker);
					}

					ch->handle_tracker_event(ev->event);

				} while (false);

				delete ev;

				cnt--;
			}
		}

	}
}
