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

#include "pump/transport/base_dialer.h"

namespace pump {
	namespace transport {

		void base_dialer::on_tracker_event(int32 ev)
		{
			if (ev == TRACKER_EVENT_DEL)
			{
				if (tracker_cnt_.fetch_sub(1) - 1 == 0)
				{
					if (__is_status(STATUS_ERROR))
						cbs_.dialed_cb(base_transport_sptr(), false);
					else if (__set_status(STATUS_TIMEOUTING, STATUS_TIMEOUTED))
						cbs_.timeout_cb();
					else if (__set_status(STATUS_STOPPING, STATUS_STOPPED))
						cbs_.stopped_cb();
				}
			}
		}

		bool base_dialer::__start_tracker(poll::channel_sptr &ch)
		{
			PUMP_ASSERT(!tracker_);

			tracker_.reset(
				object_create<poll::channel_tracker>(ch, TRACK_WRITE, TRACK_MODE_ONCE), 
				object_delete<poll::channel_tracker>
			);
			if (!get_service()->add_channel_tracker(tracker_, true))
				return false;

			tracker_cnt_.fetch_add(1);

			return true;
		}

		void base_dialer::__stop_tracker()
		{
			if (tracker_)
			{
				auto tracker = std::move(tracker_);
				PUMP_DEBUG_CHECK(get_service()->remove_channel_tracker(tracker));
			}
		}

		bool base_dialer::__start_connect_timer(const time::timer_callback &cb)
		{
			if (connect_timeout_ <= 0)
				return true;

			PUMP_ASSERT(!connect_timer_);
			connect_timer_ = time::timer::create_instance(connect_timeout_, cb);

			return get_service()->start_timer(connect_timer_);
		}

		void base_dialer::__stop_connect_timer()
		{
			if (connect_timer_)
				connect_timer_->stop();
		}

	}
}
