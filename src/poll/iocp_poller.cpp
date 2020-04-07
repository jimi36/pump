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

#include "pump/poll/iocp_poller.h"

namespace pump {
	namespace poll {

		iocp_poller::iocp_poller(bool pop_pending) :
			poller(pop_pending),
			iocp_(nullptr)
		{
#if defined (WIN32) && defined (USE_IOCP)
			iocp_ = net::get_iocp_handler();
#endif
		}

		iocp_poller::~iocp_poller()
		{
		}

		bool iocp_poller::start()
		{
#if defined(WIN32) && defined(USE_IOCP)
			if (started_.load())
				return false;

			started_.store(true);

			SYSTEM_INFO sys_info;
			GetSystemInfo(&sys_info);
			for (DWORD i = 0; i < (sys_info.dwNumberOfProcessors * 2); ++i)
			{
				std::thread *worker = new std::thread(
					function::bind(&iocp_poller::__work_thread, this)
				);
				workrs_.push_back(worker);
			}

			return true;
#else
			return false;
#endif
		}

		void iocp_poller::stop()
		{
#if defined(WIN32) && defined(USE_IOCP)
			started_.store(false);

			int32 count = (int32)workrs_.size();
			for (int32 i = 0; i < count; i++)
				PostQueuedCompletionStatus(iocp_, -1, NULL, NULL);
#endif
		}

		void iocp_poller::wait_stopped()
		{
#if defined(WIN32) && defined(USE_IOCP)
			int32 count = (int32)workrs_.size();
			for (int32 i = 0; i < count; i++)
				workrs_[i]->join();
			workrs_.clear();
#endif
		}

		bool iocp_poller::add_channel_tracker(channel_tracker_sptr &tracker)
		{
#if defined(WIN32) && defined(USE_IOCP)
			if (!started_.load())
				return false;

			auto itask = net::new_iocp_task();
			net::set_iocp_task_type(itask, IOCP_TASK_TRACKER);
			net::set_iocp_task_notifier(itask, tracker->get_channel());
			PostQueuedCompletionStatus(iocp_, 1, TRACKER_EVENT_ADD, (LPOVERLAPPED)itask);
			return true;
#else
			return false;
#endif
		}

		void iocp_poller::remove_channel_tracker(channel_tracker_sptr &tracker)
		{
#if defined(WIN32) && defined(USE_IOCP)
			auto itask = net::new_iocp_task();
			net::set_iocp_task_type(itask, IOCP_TASK_TRACKER);
			net::set_iocp_task_notifier(itask, tracker->get_channel());
			PostQueuedCompletionStatus(iocp_, 1, TRACKER_EVENT_DEL, (LPOVERLAPPED)itask);
#endif
		}

		void iocp_poller::pause_channel_tracker(channel_tracker_ptr tracker)
		{
		}

		void iocp_poller::__work_thread()
		{
#if defined(WIN32) && defined(USE_IOCP)
			int32 tracker_cnt = 0;
			DWORD transferred = 0;
			ULONG_PTR completion_key = 0;

			int32 task_type = 0;
			net::iocp_task_ptr itask = nullptr;

			while (tracker_cnt > 0 || started_.load())
			{
				if (GetQueuedCompletionStatus(iocp_, &transferred, &completion_key, (LPOVERLAPPED*)&itask, INFINITE) == TRUE)
				{
					if (!itask)
						continue;

					PUMP_LOCK_SPOINTER_EXPR(void_ch, net::get_iocp_task_notifier(itask), false,
						net::unlink_iocp_task(itask); continue);
					auto ch = (channel_ptr)void_ch;

					int32 event = IO_EVENT_NONE;
					task_type = net::get_iocp_task_type(itask);
					if (task_type == IOCP_TASK_SEND || task_type == IOCP_TASK_CONNECT)
						event |= IO_EVENT_SEND;
					else if (task_type == IOCP_TASK_READ || task_type == IOCP_TASK_ACCEPT)
						event |= IO_EVNET_READ;

					if (event != IO_EVENT_NONE)
					{
						/*
						DWORD flags = 0;
						DWORD transferred = 0;
						int32 fd = net::get_iocp_task_fd(itask);
						if (::WSAGetOverlappedResult(fd, overlapped, &transferred, FALSE, &flags) == FALSE)
						{
							PUMP_ASSERT(false);
							int32 ec = net::last_errno();
							net::set_iocp_task_ec(itask, ec);
							if (ec == WSA_IO_INCOMPLETE)
								continue;
						}
						*/

						net::set_iocp_task_processed_size(itask, transferred);

						ch->handle_io_event(event, itask);

						continue;
					}

					if (task_type == IOCP_TASK_CHANNEL)
					{
						ch->handle_channel_event(uint32(completion_key));
					}
					else if (task_type == IOCP_TASK_TRACKER)
					{
						int32 ev = (int32)completion_key;
						tracker_cnt += (ev == TRACKER_EVENT_ADD) ? 1 : -1;
						ch->handle_tracker_event(ev);
					}

					net::unlink_iocp_task(itask);
				}
				else
				{
					if (!itask)
						continue;

					PUMP_LOCK_SPOINTER_EXPR(void_ch, net::get_iocp_task_notifier(itask), false,
						net::unlink_iocp_task(itask); continue);
					auto ch = (channel_ptr)void_ch;

					int32 event = IO_EVENT_NONE;
					task_type = net::get_iocp_task_type(itask);
					if (task_type == IOCP_TASK_SEND || task_type == IOCP_TASK_CONNECT)
						event |= IO_EVENT_SEND;
					if (task_type == IOCP_TASK_READ || task_type == IOCP_TASK_ACCEPT)
						event |= IO_EVNET_READ;

					net::set_iocp_task_processed_size(itask, 0);
					net::set_iocp_task_ec(itask, net::last_errno());

					ch->handle_io_event(event, itask);
				}
			}
#endif
		}

		void iocp_poller::push_channel_event(channel_sptr &c, uint32 ev)
		{
#if defined(WIN32) && defined(USE_IOCP)
			auto itask = net::new_iocp_task();
			net::set_iocp_task_notifier(itask, c);
			net::set_iocp_task_type(itask, IOCP_TASK_CHANNEL);

			PostQueuedCompletionStatus(iocp_, 1, ev, (LPOVERLAPPED)itask);
#endif
		}

	}
}