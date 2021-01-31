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

#include "pump/debug.h"
#include "pump/poll/afd_poller.h"

#define AFD_POLL_RECEIVE           0x0001
#define AFD_POLL_RECEIVE_EXPEDITED 0x0002
#define AFD_POLL_SEND              0x0004
#define AFD_POLL_DISCONNECT        0x0008
#define AFD_POLL_ABORT             0x0010
#define AFD_POLL_LOCAL_CLOSE       0x0020
#define AFD_POLL_ACCEPT            0x0080
#define AFD_POLL_CONNECT_FAIL      0x0100

#define IOCTL_AFD_POLL             0x00012024

#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001UL
#endif

namespace pump {
namespace poll {

#if defined(PUMP_HAVE_IOCP)
    const static uint32_t AL_NONE_EVENT = 0;
    const static uint32_t AL_READ_EVENT = (AFD_POLL_ACCEPT | AFD_POLL_RECEIVE | AFD_POLL_RECEIVE_EXPEDITED | AFD_POLL_DISCONNECT | AFD_POLL_LOCAL_CLOSE | AFD_POLL_ABORT);
    const static uint32_t AL_SEND_EVENT = (AFD_POLL_SEND | AFD_POLL_DISCONNECT | AFD_POLL_LOCAL_CLOSE | AFD_POLL_ABORT | AFD_POLL_CONNECT_FAIL);
    const static uint32_t AL_ERR_EVENT  = (AFD_POLL_ABORT | AFD_POLL_CONNECT_FAIL);

#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), s }
    static UNICODE_STRING afd__device_name = RTL_CONSTANT_STRING(L"\\Device\\Afd\\poller");
#undef RTL_CONSTANT_STRING

#define RTL_CONSTANT_OBJECT_ATTRIBUTES(ObjectName, Attributes) { sizeof(OBJECT_ATTRIBUTES), NULL, ObjectName, Attributes, NULL, NULL }
    static OBJECT_ATTRIBUTES afd__device_attributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&afd__device_name, 0);
#undef RTL_CONSTANT_OBJECT_ATTRIBUTES

    HANDLE afd_create_device_handle(HANDLE iocp_handle) {
        /* By opening \Device\Afd without specifying any extended attributes, we'll
         * get a handle that lets us talk to the AFD driver, but that doesn't have an
         * associated endpoint (so it's not a socket). */
        IO_STATUS_BLOCK iosb;
        HANDLE afd_device_handle;
        NTSTATUS status = NtCreateFile(&afd_device_handle,
                            SYNCHRONIZE,
                            &afd__device_attributes,
                            &iosb,
                            NULL,
                            0,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            FILE_OPEN,
                            0,
                            NULL,
                            0);
        if (status != STATUS_SUCCESS) {
            return NULL;
        }

        if (CreateIoCompletionPort(afd_device_handle, iocp_handle, 0, 0) == NULL ||
            SetFileCompletionNotificationModes(afd_device_handle, FILE_SKIP_SET_EVENT_ON_HANDLE) == FALSE) {
            CloseHandle(afd_device_handle);
            return NULL;
        }

        return afd_device_handle;
    }
#endif

    afd_poller::afd_poller() noexcept
      : iocp_handler_(0),
        afd_device_handler_(nullptr),
        events_(nullptr),
        max_event_count_(1024) {
#if defined(PUMP_HAVE_IOCP)
        iocp_handler_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        if (!iocp_handler_) {
            PUMP_ERR_LOG("afd_poller: create iocp headler fialed");
            return;
        }

        afd_device_handler_ = afd_create_device_handle(iocp_handler_);
        if (!afd_device_handler_) {
            PUMP_ERR_LOG("afd_poller: create afd device headler fialed");
            return;
        }

        events_ = pump_malloc(sizeof(OVERLAPPED_ENTRY) * max_event_count_);
#endif
    }

    bool afd_poller::__install_channel_tracker(channel_tracker_ptr tracker) {
        if (__resume_channel_tracker(tracker)) {
            return true;
        }

        PUMP_DEBUG_LOG("afd_poller: install channel tracker failed");

        return false;

    }

    bool afd_poller::__uninstall_channel_tracker(channel_tracker_ptr tracker) {
        return true;
    }

    bool afd_poller::__resume_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_IOCP)
        auto expected_event = tracker->get_expected_event();
        auto event = tracker->get_event();
        event->Timeout.QuadPart = INT64_MAX;
        event->Exclusive = FALSE;
        event->NumberOfHandles = 1;
        event->Handles[0].Handle = (HANDLE)tracker->get_fd();
        if (expected_event & IO_EVENT_READ) {
            event->Handles[0].Events = AL_READ_EVENT;
        } else if (expected_event & IO_EVENT_SEND) {
            event->Handles[0].Events = AL_SEND_EVENT;
        }

        IO_STATUS_BLOCK iosb;
        NTSTATUS status = NtDeviceIoControlFile(
                            afd_device_handler_,
                            NULL,
                            NULL,
                            tracker,
                            &iosb,
                            IOCTL_AFD_POLL,
                            event,
                            sizeof(*event),
                            event,
                            sizeof(*event));
        if (status == STATUS_SUCCESS || status == STATUS_PENDING) {
            return true;
        }

        PUMP_DEBUG_LOG("afd_poller: resume channel tracker fialed %d", net::last_errno());
#else
        PUMP_ERR_LOG("afd_poller: resume channel tracker failed for not support");
#endif
        return false;
    }

    void afd_poller::__poll(int32_t timeout) {
#if defined(PUMP_HAVE_IOCP)
        DWORD completion_count = 0;
        LPOVERLAPPED_ENTRY iocp_events = (LPOVERLAPPED_ENTRY)events_;
        BOOL ret = GetQueuedCompletionStatusEx(iocp_handler_,
                                               iocp_events,
                                               max_event_count_,
                                               &completion_count,
                                               timeout,
                                               FALSE);
        if (!ret) {
            return;
        }

        if (completion_count > 0) {
            __dispatch_pending_event(completion_count);
        }
#endif
    }

    void afd_poller::__dispatch_pending_event(int32_t count) {
#if defined(PUMP_HAVE_IOCP)
        channel_tracker_ptr tracker;
        auto ev_beg = (LPOVERLAPPED_ENTRY)events_;
        auto ev_end = (LPOVERLAPPED_ENTRY)events_ + count;
        for (auto ev = ev_beg; ev != ev_end; ++ev) {
            // If channel is invalid, tracker should be removed.
            tracker = (channel_tracker_ptr)ev->lpOverlapped;
            if (tracker->untrack()) {
                auto ch = tracker->get_channel();
                if (ch) {
                    ch->handle_io_event(tracker->get_expected_event());
                }
            }
        }
#endif
    }
}
}