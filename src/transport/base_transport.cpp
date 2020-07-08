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

#include "pump/transport/base_transport.h"

namespace pump {
	namespace transport {

		bool base_transport::reset_callbacks(const transport_callbacks &cbs)
		{
			if (!is_started())
				return false;

			PUMP_ASSERT(cbs.read_cb || cbs.read_from_cb);
			PUMP_ASSERT(cbs.disconnected_cb && cbs.stopped_cb);
			cbs_ = cbs;

			return true;
		}

		void base_transport::pause_read()
		{
			if (is_started())
			{
				auto tracker = r_tracker_;
				if (!tracker)
					return;

				get_service()->pause_channel_tracker(tracker.get());

				read_paused_.store(true);
			}
		}

		transport_error base_transport::continue_read()
		{
			if (PUMP_UNLIKELY(!is_started()))
				return ERROR_UNSTART;

			PUMP_LOCK_SPOINTER(tracker, r_tracker_);
			if (tracker == nullptr)
				return ERROR_INVALID;

			bool paused = true;
			if (!read_paused_.compare_exchange_strong(paused, false))
				return ERROR_INVALID;

			get_service()->awake_channel_tracker(tracker);

			return ERROR_OK;
		}

		void base_transport::on_tracker_event(int32 ev)
		{
			if (ev == TRACKER_EVENT_DEL)
			{
				if (tracker_cnt_.fetch_sub(1) - 1 == 0)
				{
					if (__set_status(STATUS_DISCONNECTING, STATUS_DISCONNECTED))
						cbs_.disconnected_cb();
					else if (__set_status(STATUS_STOPPING, STATUS_STOPPED))
						cbs_.stopped_cb();
				}
			}
		}

		bool base_transport::__start_all_trackers(poll::channel_sptr &ch, bool rt, bool wt)
		{
			PUMP_ASSERT(!r_tracker_ && !s_tracker_);
			r_tracker_.reset(
				object_create<poll::channel_tracker>(ch, TRACK_READ, TRACK_MODE_LOOP),
				object_delete<poll::channel_tracker>
			);
			s_tracker_.reset(
				object_create<poll::channel_tracker>(ch, TRACK_WRITE, TRACK_MODE_ONCE),
				object_delete<poll::channel_tracker>
			);
			if (!get_service()->add_channel_tracker(r_tracker_, rt) || 
				!get_service()->add_channel_tracker(s_tracker_, wt))
				return false;

			tracker_cnt_.fetch_add(2);

			return true;
		}

		bool base_transport::__awake_tracker(poll::channel_tracker_sptr tracker)
		{
			if (!tracker)
				return false;

			PUMP_DEBUG_CHECK(get_service()->awake_channel_tracker(tracker.get()));

			return true;
		}

		bool base_transport::__pause_tracker(poll::channel_tracker_sptr tracker)
		{
			if (!tracker)
				return false;

			PUMP_DEBUG_CHECK(get_service()->pause_channel_tracker(tracker.get()));

			return true;
		}

		void base_transport::__stop_read_tracker()
		{
			if (r_tracker_)
			{
				auto tracker = std::move(r_tracker_);
				PUMP_DEBUG_CHECK(get_service()->remove_channel_tracker(tracker));
			}
		}

		void base_transport::__stop_send_tracker()
		{
			if (s_tracker_)
			{
				auto tracker = std::move(s_tracker_);
				PUMP_DEBUG_CHECK(get_service()->remove_channel_tracker(tracker));
			}
		}

	}
}
