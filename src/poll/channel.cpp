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

#include "librabbit/poll/channel.h"

namespace librabbit {
	namespace poll {

		channel::channel(int32 fd) :
			ctx_(nullptr),
			fd_(fd)
		{
		}

		channel::~channel()
		{
		}

		void channel::handle_io_event(uint32 event, net::iocp_task_ptr itask)
		{
			if (event & IO_EVNET_READ)
				on_read_event(itask);
			if (event & IO_EVENT_WRITE)
				on_write_event(itask);
			if (event & IO_EVENT_ERROR)
				on_error_event();
		}

		void channel::handle_tracker_event(uint32 on)
		{
			on_tracker_event(on);
		}

	}
}
