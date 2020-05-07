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


#include "pump/transport/base_acceptor.h"

namespace pump {
	namespace transport {

		void base_acceptor::on_tracker_event(int32 ev)
		{
			if (ev == TRACKER_EVENT_ADD)
				return;

			if (ev == TRACKER_EVENT_DEL)
			{

				if (tracker_cnt_.fetch_sub(1) - 1 == 0)
				{
					if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED))
						cbs_.stopped_cb();
				}
			}
		}

		bool base_acceptor::__start_tracker(poll::channel_sptr &ch)
		{
			PUMP_ASSERT(!tracker_);

			tracker_.reset(new poll::channel_tracker(ch, TRACK_READ, TRACK_MODE_LOOP));
			if (!get_service()->add_channel_tracker(tracker_, true))
				return false;

			tracker_cnt_.fetch_add(1);

			return true;
		}

		void base_acceptor::__stop_tracker()
		{
			if (tracker_)
			{
				auto tracker = std::move(tracker_);
				PUMP_DEBUG_CHECK(get_service()->remove_channel_tracker(tracker));
			}
		}

	}
}
