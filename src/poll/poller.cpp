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

		poller::poller(bool pop_pending): 
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

		void poller::stop()
		{
			started_.store(false);
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
			if (!started_.load())
				return false;

			tracker->__set_tracking(tracking);

			auto tev = new channel_tracker_event(tracker, TRACKER_EVENT_ADD);
			if (!tevents_.enqueue(tev))
				PUMP_ASSERT(false);
			tev_cnt_++;

			return true;
		}

		void poller::remove_channel_tracker(channel_tracker_sptr &tracker)
		{
			auto tev = new channel_tracker_event(tracker, TRACKER_EVENT_DEL);
			if (!tevents_.enqueue(tev))
				PUMP_ASSERT(false);
			tev_cnt_++;
		}

		void poller::pause_channel_tracker(channel_tracker_ptr tracker)
		{
			PUMP_ASSERT(tracker);
			tracker->__set_tracking(false);

			__pause_channel_tracker(tracker);
		}

		void poller::awake_channel_tracker(channel_tracker_ptr tracker)
		{
			PUMP_ASSERT(tracker);
			tracker->__set_tracking(true);

			__awake_channel_tracker(tracker);
		}

		void poller::push_channel_event(channel_sptr &c, uint32 event)
		{
			if (!started_.load())
				return;

			auto cev = new channel_event(c, event);
			if (!cevents_.enqueue(cev))
				PUMP_ASSERT(false);
			cev_cnt_++;
		}

		void poller::__handle_channel_events()
		{
			channel_event *ev = nullptr;
			auto cnt = cev_cnt_.exchange(0);
			while (cnt > 0 && cevents_.try_dequeue(ev))
			{
				PUMP_LOCK_WPOINTER_EXPR(ch, ev->ch, false, break);
				ch->handle_channel_event(ev->event);

				delete ev;
			}
		}

		void poller::__handle_channel_tracker_events()
		{
			auto cnt = tev_cnt_.exchange(0);
			channel_tracker_event *ev = nullptr;
			while (cnt > 0 && tevents_.try_dequeue(ev))
			{
				do 
				{
					auto tracker = ev->tracker.get();
					PUMP_ASSERT(tracker);

					PUMP_LOCK_SPOINTER_EXPR(ch, tracker->get_channel(), false, break);

					if (ev->event == TRACKER_EVENT_ADD)
					{
						PUMP_ASSERT(tracker->get_fd() > 0);

						if (tracker->is_tracking())
						{
							if (!__add_channel_tracker(tracker))
								PUMP_ASSERT(false);
						}

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
			}
		}

	}
}
