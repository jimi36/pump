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

#include "librabbit/poll/iocp_poller.h"

namespace librabbit {
	namespace poll {

		iocp_poller::iocp_poller(bool pop_pending) :
			poller(pop_pending),
			iocp_(NULL)
		{
#ifdef WIN32
			iocp_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
#endif
		}

		iocp_poller::~iocp_poller()
		{
#ifdef WIN32
			if (iocp_)
				CloseHandle(iocp_);
#endif
		}

		bool iocp_poller::start()
		{
#ifdef WIN32
			is_started_ = true;

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
#ifdef WIN32
			is_started_ = false;

			int32 count = (int32)workrs_.size();
			for (int32 i = 0; i < count; i++)
				PostQueuedCompletionStatus(iocp_, -1, NULL, NULL);
#endif
		}

		void iocp_poller::wait_stop()
		{
#ifdef WIN32
			int32 count = (int32)workrs_.size();
			for (int32 i = 0; i < count; i++)
				workrs_[i]->join();
			workrs_.clear();
#endif
		}

		void iocp_poller::add_channel_tracker(channel_tracker_sptr &tracker)
		{
#ifdef WIN32
			auto itask = net::new_iocp_task();
			net::set_iocp_task_type(itask, IOCP_TASK_TRACKER);
			net::set_iocp_task_notifier(itask, tracker->get_channel());

			PostQueuedCompletionStatus(iocp_, 1, 1, (LPOVERLAPPED)itask);
#endif
		}

		void iocp_poller::remove_channel_tracker(channel_tracker_sptr &tracker)
		{
#ifdef WIN32
			auto itask = net::new_iocp_task();
			net::set_iocp_task_type(itask, IOCP_TASK_TRACKER);
			net::set_iocp_task_notifier(itask, tracker->get_channel());

			PostQueuedCompletionStatus(iocp_, 1, 0, (LPOVERLAPPED)itask);
#endif
		}

		void iocp_poller::__work_thread()
		{
#ifdef WIN32
			while (is_started_)
			{
				DWORD transferred = 0;
				ULONG_PTR completion_key = 0;
				LPOVERLAPPED overlapped = NULL;
				if (GetQueuedCompletionStatus(iocp_, &transferred, &completion_key, (LPOVERLAPPED*)&overlapped, INFINITE) == TRUE)
				{
					if (transferred == -1)
						continue;

					auto itask = (net::iocp_task_ptr)overlapped;
					auto ch_locker = static_pointer_cast<channel>(net::get_iocp_task_notifier(itask).lock());
					auto ch = ch_locker.get();
					if (ch == nullptr)
					{
						net::unlink_iocp_task(itask);
						continue;
					}

					int32 task_type = net::get_iocp_task_type(itask);
					if (task_type == IOCP_TASK_EVNET)
					{
						ch->on_channel_event(uint32(completion_key));
						net::unlink_iocp_task(itask);
						continue;
					}
					else if (task_type == IOCP_TASK_TRACKER)
					{
						ch->handle_tracker_event(bool(completion_key));
						net::unlink_iocp_task(itask);
						continue;
					}

					DWORD flags = 0;
					DWORD transferred = 0;
					int32 fd = net::get_iocp_task_fd(itask);
					if (WSAGetOverlappedResult(fd, overlapped, &transferred, FALSE, &flags) == FALSE)
					{
						int32 ec = net::last_errno();
						net::set_iocp_task_ec(itask, ec);
						if (ec == WSA_IO_INCOMPLETE)
							continue;
					}

					net::set_iocp_task_processed_size(itask, transferred);

					int32 event = IO_EVENT_NONE;
					if (task_type == IOCP_TASK_SEND || task_type == IOCP_TASK_CONNECT)
						event |= IO_EVENT_WRITE;
					if (task_type == IOCP_TASK_RECV || task_type == IOCP_TASK_ACCEPT)
						event |= IO_EVNET_READ;
					ch->handle_io_event(event, itask);
				}
				else
				{
					auto itask = (net::iocp_task_ptr)overlapped;
					if (itask == nullptr)
						continue;

					auto ch_locker = static_pointer_cast<channel>(net::get_iocp_task_notifier(itask).lock());
					auto ch = ch_locker.get();
					if (ch == nullptr)
					{
						net::unlink_iocp_task(itask);
						continue;
					}

					net::set_iocp_task_processed_size(itask, 0);
					net::set_iocp_task_ec(itask, net::last_errno());

					int32 task_type = net::get_iocp_task_type(itask);
					int32 event = IO_EVENT_NONE;
					if (task_type == IOCP_TASK_SEND || task_type == IOCP_TASK_CONNECT)
						event |= IO_EVENT_WRITE;
					if (task_type == IOCP_TASK_RECV || task_type == IOCP_TASK_ACCEPT)
						event |= IO_EVNET_READ;
					ch->handle_io_event(event, itask);
				}
			}
#endif
		}

		void iocp_poller::push_channel_event(channel_sptr &c, uint32 event)
		{
#ifdef WIN32
			auto itask = net::new_iocp_task();
			net::set_iocp_task_notifier(itask, c);
			net::set_iocp_task_type(itask, IOCP_TASK_EVNET);

			PostQueuedCompletionStatus(iocp_, 1, event, (LPOVERLAPPED)itask);
#endif
		}

	}
}