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

		void base_transport::on_tracker_event(int32 ev)
		{
			if (ev == TRACKER_EVENT_ADD)
				return;

			if (ev == TRACKER_EVENT_DEL)
				tracker_cnt_ -= 1;

			if (tracker_cnt_ == 0)
			{
				if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_DISCONNECTED))
					cbs_.disconnected_cb();
				else if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED))
					cbs_.stopped_cb();
			}
		}

		bool base_transport::__start_all_trackers(poll::channel_sptr &ch)
		{
			PUMP_ASSERT(!r_tracker_ && !s_tracker_);
			r_tracker_.reset(new poll::channel_tracker(ch, TRACK_READ, TRACK_MODE_LOOP));
			s_tracker_.reset(new poll::channel_tracker(ch, TRACK_WRITE, TRACK_MODE_ONCE));
			if (!get_service()->add_channel_tracker(s_tracker_, false) ||
				!get_service()->add_channel_tracker(r_tracker_, true))
				return false;

			tracker_cnt_.fetch_add(2);

			return true;
		}

		bool base_transport::__awake_tracker(poll::channel_tracker_sptr tracker)
		{
			if (PUMP_UNLIKELY(!tracker))
				return false;
			else
				PUMP_DEBUG_CHECK(get_service()->awake_channel_tracker(tracker.get()));

			return true;
		}

		bool base_transport::__pause_tracker(poll::channel_tracker_sptr tracker)
		{
			if (PUMP_UNLIKELY(!tracker))
				return false;
			else
				PUMP_DEBUG_CHECK(get_service()->pause_channel_tracker(tracker.get()));

			return true;
		}

		void base_transport::__stop_read_tracker()
		{
			if (r_tracker_)
				PUMP_DEBUG_CHECK(get_service()->remove_channel_tracker(std::move(r_tracker_)));
		}

		void base_transport::__stop_send_tracker()
		{
			if (s_tracker_)
				PUMP_DEBUG_CHECK(get_service()->remove_channel_tracker(std::move(s_tracker_)));
		}

	}
}