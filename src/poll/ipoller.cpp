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

#include "pump/poll/ipoller.h"

namespace pump {
namespace poll {

    iocp_poller::iocp_poller() noexcept : iocp_(nullptr) {
#if defined(PUMP_HAVE_IOCP)
        iocp_ = net::get_iocp_handler();
#endif
    }

    iocp_poller::~iocp_poller() {
    }

    bool iocp_poller::start() {
#if defined(PUMP_HAVE_IOCP)
        if (started_.load()) {
            PUMP_ERR_LOG("net::iocp_poller::start: already started");
            return false;
        }

        started_.store(true);

        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);
        for (DWORD i = 0; i < (sys_info.dwNumberOfProcessors * 2); ++i) {
            std::thread *worker =
                object_create<std::thread>(pump_bind(&iocp_poller::__work_thread, this));
            workrs_.push_back(worker);
        }

        return true;
#else
        PUMP_ERR_LOG("net::iocp_poller::start: not support");
        return false;
#endif
    }

    void iocp_poller::stop() {
#if defined(PUMP_HAVE_IOCP)
        started_.store(false);

        int32 count = (int32)workrs_.size();
        for (int32 i = 0; i < count; i++)
            PostQueuedCompletionStatus(iocp_, -1, NULL, NULL);
#endif
    }

    void iocp_poller::wait_stopped() {
#if defined(PUMP_HAVE_IOCP)
        int32 count = (int32)workrs_.size();
        for (int32 i = 0; i < count; i++)
            workrs_[i]->join();
        workrs_.clear();
#endif
    }

    void iocp_poller::__work_thread() {
#if defined(PUMP_HAVE_IOCP)
        int32 tracker_cnt = 0;
        DWORD transferred = 0;
        ULONG_PTR completion_key = 0;

        int32 ttp = 0;
        void_ptr task = nullptr;

        while (tracker_cnt > 0 || started_.load()) {
            if (GetQueuedCompletionStatus(iocp_,
                                          &transferred,
                                          &completion_key,
                                          (LPOVERLAPPED *)&task,
                                          INFINITE) == TRUE) {
                if (!task) {
                    PUMP_WARN_LOG("net::iocp_poller::__work_thread: task invalid");
                    continue;
                }

                PUMP_LOCK_SPOINTER(vptr, net::get_iocp_task_notifier(task));
                if (vptr == nullptr) {
                    PUMP_WARN_LOG(
                        "net::iocp_poller::__work_thread: task channel notifier invalid");
                    net::unlink_iocp_task(task);
                    continue;
                }

                int32 event = IO_EVENT_NONE;
                ttp = net::get_iocp_task_type(task);
                if (ttp == IOCP_TASK_SEND || ttp == IOCP_TASK_CONNECT)
                    event |= IO_EVENT_SEND;
                else if (ttp == IOCP_TASK_READ || ttp == IOCP_TASK_ACCEPT)
                    event |= IO_EVNET_READ;

                auto ch = (channel_ptr)vptr;
                if (event != IO_EVENT_NONE) {
                    net::set_iocp_task_processed_size(task, transferred);
                    ch->handle_io_event(event, task);
                } else {
                    if (ttp == IOCP_TASK_CHANNEL) {
                        ch->handle_channel_event(uint32(completion_key));
                    } else if (ttp == IOCP_TASK_TRACKER) {
                        int32 ev = (int32)completion_key;
                        tracker_cnt += (ev == TRACKER_EVENT_ADD) ? 1 : -1;
                        ch->handle_tracker_event(ev);
                    }
                }
            } else {
                if (!task) {
                    PUMP_DEBUG_LOG("net::iocp_poller::__work_thread: task invalid");
                    continue;
                }

                PUMP_LOCK_SPOINTER(vptr, net::get_iocp_task_notifier(task));
                if (vptr == nullptr) {
                    PUMP_DEBUG_LOG(
                        "net::iocp_poller::__work_thread: task channel notifier invalid");
                    net::unlink_iocp_task(task);
                    continue;
                }

                int32 event = IO_EVENT_NONE;
                ttp = net::get_iocp_task_type(task);
                if (ttp == IOCP_TASK_SEND || ttp == IOCP_TASK_CONNECT)
                    event |= IO_EVENT_SEND;
                else if (ttp == IOCP_TASK_READ || ttp == IOCP_TASK_ACCEPT)
                    event |= IO_EVNET_READ;

                net::set_iocp_task_processed_size(task, 0);
                net::set_iocp_task_ec(task, net::last_errno());

                auto ch = (channel_ptr)vptr;
                ch->handle_io_event(event, task);
            }

            net::unlink_iocp_task(task);
        }
#endif
    }

    void iocp_poller::push_channel_event(channel_sptr &c, uint32 ev) {
#if defined(PUMP_HAVE_IOCP)
        auto task = net::new_iocp_task();
        net::set_iocp_task_notifier(task, c);
        net::set_iocp_task_type(task, IOCP_TASK_CHANNEL);

        PostQueuedCompletionStatus(iocp_, 1, ev, (LPOVERLAPPED)task);
#endif
    }

}  // namespace poll
}  // namespace pump