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

    iocp_poller::iocp_poller() noexcept
      : iocp_(nullptr) {
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

        //SYSTEM_INFO sys_info;
        //GetSystemInfo(&sys_info);
        //for (DWORD i = 0; i < (sys_info.dwNumberOfProcessors * 2); ++i) {
        for (int32 i = 0; i < 2; ++i) {
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
#endif
    }

    void iocp_poller::wait_stopped() {
#if defined(PUMP_HAVE_IOCP)
        int32 count = (int32)workrs_.size();
        for (int32 i = 0; i < count; i++) {
            workrs_[i]->join();
        }
        workrs_.clear();
#endif
    }

    void iocp_poller::__work_thread() {
#if defined(PUMP_HAVE_IOCP)
        DWORD transferred = 0;
        ULONG_PTR completion_key = 0;
        net::iocp_task_ptr task = nullptr;

        while (started_.load()) {
            if (GetQueuedCompletionStatus(iocp_,
                                          &transferred,
                                          &completion_key,
                                          (LPOVERLAPPED *)&task,
                                          1000) == TRUE) {
                PUMP_ASSERT(task);
 
                PUMP_LOCK_SPOINTER(notifier, task->get_notifier());
                if (!notifier) {
                    PUMP_WARN_LOG(
                        "iocp_poller::__work_thread: task channel notifier invalid");
                    task->sub_link();
                    continue;
                }

                int32 event = IO_EVENT_NONE;
                int32 task_type = task->get_type();
                if (task_type & net::IOCP_READ_MASKS) {
                    event = IO_EVENT_READ;
                } else if (task_type & net::IOCP_SEND_MASKS) {
                    event = IO_EVENT_SEND;
                }

                if (event != IO_EVENT_NONE) {
                    task->set_processed_size(transferred);
                    channel_ptr(notifier)->handle_io_event(event, task);
                } else {
                    channel_ptr(notifier)->handle_channel_event(uint32(completion_key));
                }
            } else {
                if (!task) {
                    continue;
                }

                PUMP_LOCK_SPOINTER(notifier, task->get_notifier());
                if (!notifier) {
                    PUMP_DEBUG_LOG(
                        "iocp_poller::__work_thread: task channel notifier invalid");
                    task->sub_link();
                    continue;
                }

                int32 event = IO_EVENT_NONE;
                int32 task_type = task->get_type();
                if (task_type & net::IOCP_READ_MASKS) {
                    event = IO_EVENT_READ;
                } else if (task_type & net::IOCP_SEND_MASKS) {
                    event = IO_EVENT_SEND;
                }

                task->set_processed_size(0);
                task->set_errcode(net::last_errno());

                channel_ptr(notifier)->handle_io_event(event, task);
            }

            task->sub_link();
        }
#endif
    }

    bool iocp_poller::push_channel_event(channel_sptr &c, uint32 ev) {
#if defined(PUMP_HAVE_IOCP)
        auto task = net::new_iocp_task();
        task->set_notifier(c);
        task->set_type(net::IOCP_TASK_CHANNEL);
        return PostQueuedCompletionStatus(iocp_, 1, ev, (LPOVERLAPPED)task) == TRUE;
#else
        return false;
#endif
    }

}  // namespace poll
}  // namespace pump