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

#include "librabbit/poll/poller.h"

namespace librabbit {
	namespace poll {

		poller::poller(bool pop_pending): 
			is_started_(false),
			pop_pending_channel_(pop_pending),
			ch_event_cnt_(0)
		{
		}

		poller::~poller()
		{
			for (auto ch_event: ch_events_)
			{
				delete ch_event;
			}
		}

		bool poller::start()
		{
			if (is_started_)
				return false;

			is_started_ = true;

			worker_.reset(new std::thread([&]() {
				while (is_started_)
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
			is_started_ = false;
		}

		void poller::wait_stop()
		{
			if (worker_)
			{
				worker_->join();
				worker_.reset();
			}
		}

		void poller::add_channel_tracker(channel_tracker_sptr &tracker)
		{
			std::lock_guard<std::mutex> locker(tracker_mx_);
			tracker_modifiers_.push_back(std::move(channel_tracker_modifier(tracker, true)));
		}

		void poller::remove_channel_tracker(channel_tracker_sptr &tracker)
		{
			std::lock_guard<std::mutex> locker(tracker_mx_);
			tracker_modifiers_.push_back(std::move(channel_tracker_modifier(tracker, false)));
		}

		void poller::awake_channel_tracker(channel_tracker_sptr &tracker)
		{
			__awake_channel_tracker(tracker.get());
		}

		void poller::push_channel_event(channel_sptr &c, uint32 event)
		{
			auto ev = new channel_event(c, event);
			std::lock_guard<std::mutex> locker(ch_event_mx_);
			ch_events_.push_back(ev);
			ch_event_cnt_++;
		}

		void poller::__handle_channel_events()
		{
			if (ch_event_cnt_ == 0)
				return;

			std::list<channel_event_ptr> ch_events;
			{
				std::lock_guard<std::mutex> locker(ch_event_mx_);
				ch_events.swap(ch_events_);
				ch_event_cnt_ = 0;
			}

			for (auto ev: ch_events)
			{
				auto ch = ev->ch.lock();
				if (ch)
					ch->on_channel_event(ev->event);

				delete ev;
			}
		}

		void poller::__update_channel_trackers()
		{
			std::vector<channel_tracker_modifier> tracker_modifiers;
			{
				std::lock_guard<std::mutex> locker(tracker_mx_);
				tracker_modifiers.swap(tracker_modifiers_);
			}

			for (channel_tracker_modifier &modifier : tracker_modifiers)
			{
				auto tracker = modifier.tracker.get();
				auto ch_locker = tracker->get_channel();
				auto ch = ch_locker.get();

				assert(tracker->get_fd() > 0);

				if (modifier.on)
				{
					assert(ch);
					if (__add_channel_tracker(tracker))
						trackers_[tracker] = modifier.tracker;
				}
				else 
				{
					__remove_channel_tracker(tracker);

					trackers_.erase(tracker);
				}

				if (ch)
					ch->handle_tracker_event(modifier.on);
			}
		}

	}
}
