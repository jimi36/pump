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
			has_ch_event_(false),
			has_tr_event_(false)
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

					__update_channel_trackers();

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

		bool poller::add_channel_tracker(channel_tracker_sptr &tracker)
		{
			if (!started_.load())
				return false;

			tracker->set_tracking(true);

			std::lock_guard<std::mutex> locker(tracker_mx_);
			//std::lock_guard<utils::spin_mutex> locker(tracker_mx_);
			tr_events_.push_back(channel_tracker_event(tracker, TRACKER_EVENT_ADD));
			has_tr_event_ = true;

			return true;
		}

		void poller::remove_channel_tracker(channel_tracker_sptr &tracker)
		{
			std::lock_guard<std::mutex> locker(tracker_mx_);
			//std::lock_guard<utils::spin_mutex> locker(tracker_mx_);
			tr_events_.push_back(channel_tracker_event(tracker, TRACKER_EVENT_DEL));
			has_tr_event_ = true;
		}

		void poller::pause_channel_tracker(channel_tracker_ptr tracker)
		{
			PUMP_ASSERT(tracker);
			tracker->set_tracking(false);

			__pause_channel_tracker(tracker);
		}

		void poller::awake_channel_tracker(channel_tracker_ptr tracker)
		{
			PUMP_ASSERT(tracker);
			tracker->set_tracking(true);

			__awake_channel_tracker(tracker);
		}

		void poller::push_channel_event(channel_sptr &c, uint32 event)
		{
			if (!started_.load())
				return;

			std::lock_guard<std::mutex> locker(ch_event_mx_);
			//std::lock_guard<utils::spin_mutex> locker(ch_event_mx_);
			ch_events_.push_back(channel_event(c, event));
			has_ch_event_ = true;
		}

		void poller::__handle_channel_events()
		{
			if (!has_ch_event_)
				return;

			std::vector<channel_event> ch_events;
			{
				std::lock_guard<std::mutex> locker(ch_event_mx_);
				//std::lock_guard<utils::spin_mutex> locker(ch_event_mx_);
				ch_events.swap(ch_events_);
				has_ch_event_ = false;
			}

			for (channel_event &ev: ch_events)
			{
				auto ch_locker = ev.ch.lock();
				auto ch = ch_locker.get();
				if (ch)
					ch->handle_channel_event(ev.event);
			}
		}

		void poller::__update_channel_trackers()
		{
			if (!has_tr_event_)
				return;

			std::vector<channel_tracker_event> new_events;
			{
				std::lock_guard<std::mutex> locker(tracker_mx_);
				//std::lock_guard<utils::spin_mutex> locker(tracker_mx_);
				new_events.swap(tr_events_);
				has_tr_event_ = false;
			}

			for (channel_tracker_event &ev: new_events)
			{
				auto tracker = ev.tracker.get();

				PUMP_LOCK_SPOINTER_EXPR(ch, tracker->get_channel(), false,
					continue);

				if (ev.event == TRACKER_EVENT_ADD)
				{
					if (tracker->get_fd() <= 0)
						continue;

					if (__add_channel_tracker(tracker))
						trackers_[tracker] = ev.tracker;
				}
				else if (ev.event == TRACKER_EVENT_DEL)
				{
					__remove_channel_tracker(tracker);
					trackers_.erase(tracker);
				}

				// All tracker opt will trigger tracker event, even if the tracker is not in the 
				// poller tracker list. But channel of the tracker must be existing.
				ch->handle_tracker_event(ev.event);
			}
		}

	}
}
