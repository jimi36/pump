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

#define AFD_POLL_RECEIVE_BIT            0
#define AFD_POLL_RECEIVE                (1 << AFD_POLL_RECEIVE_BIT)
#define AFD_POLL_RECEIVE_EXPEDITED_BIT  1
#define AFD_POLL_RECEIVE_EXPEDITED      (1 << AFD_POLL_RECEIVE_EXPEDITED_BIT)
#define AFD_POLL_SEND_BIT               2
#define AFD_POLL_SEND                   (1 << AFD_POLL_SEND_BIT)
#define AFD_POLL_DISCONNECT_BIT         3
#define AFD_POLL_DISCONNECT             (1 << AFD_POLL_DISCONNECT_BIT)
#define AFD_POLL_ABORT_BIT              4
#define AFD_POLL_ABORT                  (1 << AFD_POLL_ABORT_BIT)
#define AFD_POLL_LOCAL_CLOSE_BIT        5
#define AFD_POLL_LOCAL_CLOSE            (1 << AFD_POLL_LOCAL_CLOSE_BIT)
#define AFD_POLL_CONNECT_BIT            6
#define AFD_POLL_CONNECT                (1 << AFD_POLL_CONNECT_BIT)
#define AFD_POLL_ACCEPT_BIT             7
#define AFD_POLL_ACCEPT                 (1 << AFD_POLL_ACCEPT_BIT)
#define AFD_POLL_CONNECT_FAIL_BIT       8
#define AFD_POLL_CONNECT_FAIL           (1 << AFD_POLL_CONNECT_FAIL_BIT)
#define AFD_POLL_QOS_BIT                9
#define AFD_POLL_QOS                    (1 << AFD_POLL_QOS_BIT)
#define AFD_POLL_GROUP_QOS_BIT          10
#define AFD_POLL_GROUP_QOS              (1 << AFD_POLL_GROUP_QOS_BIT)

#define AFD_NUM_POLL_EVENTS             11
#define AFD_POLL_ALL                    ((1 << AFD_NUM_POLL_EVENTS) - 1)

#define AFD_RECEIVE             5
#define AFD_RECEIVE_DATAGRAM    6
#define AFD_POLL                9

#define FSCTL_AFD_BASE FILE_DEVICE_NETWORK
#define _AFD_CONTROL_CODE(operation, method) \
    ((FSCTL_AFD_BASE) << 12 | (operation << 2) | method)

#define IOCTL_AFD_RECEIVE \
    _AFD_CONTROL_CODE(AFD_RECEIVE, METHOD_NEITHER)
#define IOCTL_AFD_RECEIVE_DATAGRAM \
    _AFD_CONTROL_CODE(AFD_RECEIVE_DATAGRAM, METHOD_NEITHER)
#define IOCTL_AFD_POLL \
    _AFD_CONTROL_CODE(AFD_POLL, METHOD_BUFFERED)

#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001UL
#endif

namespace pump {
namespace poll {

#if defined(PUMP_HAVE_IOCP)
    const static uint32_t AL_NONE_EVENT = 0;
    const static uint32_t AL_READ_EVENT = (AFD_POLL_ACCEPT | AFD_POLL_RECEIVE | AFD_POLL_RECEIVE_EXPEDITED | AFD_POLL_LOCAL_CLOSE  | AFD_POLL_DISCONNECT | AFD_POLL_ABORT);
    const static uint32_t AL_SEND_EVENT = (AFD_POLL_SEND | AFD_POLL_DISCONNECT | AFD_POLL_CONNECT_FAIL);
    const static uint32_t AL_ERR_EVENT  = (AFD_POLL_ABORT | AFD_POLL_CONNECT_FAIL);

#define RTL_CONSTANT_STRING(s) \
    { sizeof(s) - sizeof((s)[0]), sizeof(s), (PWSTR)s }
    static UNICODE_STRING afd__device_name = RTL_CONSTANT_STRING(L"\\Device\\Afd\\Poller");
#undef RTL_CONSTANT_STRING

#define RTL_CONSTANT_OBJECT_ATTRIBUTES(ObjectName, Attributes) \
    { sizeof(OBJECT_ATTRIBUTES), NULL, ObjectName, Attributes, NULL, NULL }
    static OBJECT_ATTRIBUTES afd__device_attributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&afd__device_name, 0);
#undef RTL_CONSTANT_OBJECT_ATTRIBUTES

    HANDLE afd_create_device_handle(HANDLE iocp_handle) {
        /* 
         * By opening \Device\Afd without specifying any extended attributes, we'll
         * get a handle that lets us talk to the AFD driver, but that doesn't have an
         * associated endpoint (so it's not a socket). 
         */
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
      : iocp_handler_(NULL),
        afd_device_handler_(NULL),
        events_(nullptr),
        max_event_count_(1024),
        cur_event_count_(0) {
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

    afd_poller::~afd_poller() {
#if defined(PUMP_HAVE_IOCP)
        if (afd_device_handler_) {
            CloseHandle(afd_device_handler_);
        }
        if (iocp_handler_) {
            CloseHandle(iocp_handler_);
        }
#endif
    }

    bool afd_poller::__install_channel_tracker(channel_tracker_ptr tracker) {
        if (__resume_channel_tracker(tracker)) {
            cur_event_count_.fetch_add(1, std::memory_order_relaxed);
            return true;
        }

        PUMP_DEBUG_LOG("afd_poller: install channel tracker failed");

        return false;
    }

    bool afd_poller::__uninstall_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_IOCP)
        auto event = tracker->get_event();

        if (event->iosb.Status != STATUS_PENDING) {
            cur_event_count_.fetch_sub(1, std::memory_order_relaxed);
            return true;
        }

        IO_STATUS_BLOCK cancel_iosb;
        NTSTATUS cancel_status = NtCancelIoFileEx(afd_device_handler_, 
                                                  &(event->iosb), 
                                                  &cancel_iosb);
        if (cancel_status == STATUS_SUCCESS || cancel_status == STATUS_NOT_FOUND) {
            cur_event_count_.fetch_sub(1, std::memory_order_relaxed);
            return true;
        }
#endif
        return false;
    }

    bool afd_poller::__resume_channel_tracker(channel_tracker_ptr tracker) {
#if defined(PUMP_HAVE_IOCP)
        auto expected_event = tracker->get_expected_event();
        auto event = tracker->get_event();
        event->info.Timeout.QuadPart = INT64_MAX;
        event->info.Exclusive = FALSE;
        event->info.NumberOfHandles = 1;
        event->info.Handles[0].Status = 0;
        event->info.Handles[0].Handle = (HANDLE)tracker->get_fd();
        if (expected_event & IO_EVENT_READ) {
            event->info.Handles[0].Events = AL_READ_EVENT;
        } else if (expected_event & IO_EVENT_SEND) {
            event->info.Handles[0].Events = AL_SEND_EVENT;
        }
        event->iosb.Status = STATUS_PENDING;

        NTSTATUS status = NtDeviceIoControlFile(afd_device_handler_,
                                                NULL,
                                                NULL,
                                                tracker,
                                                &(event->iosb),
                                                IOCTL_AFD_POLL,
                                                &(event->info),
                                                sizeof(event->info),
                                                event,
                                                sizeof(event->info));
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
        auto cur_event_count = cur_event_count_.load(std::memory_order_relaxed);
        if (PUMP_UNLIKELY(cur_event_count > max_event_count_)) {
            max_event_count_ = cur_event_count;
            events_ = pump_realloc(events_, sizeof(OVERLAPPED_ENTRY) * max_event_count_);
            PUMP_ASSERT(events_);
        }

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
        auto ev_beg = (LPOVERLAPPED_ENTRY)events_;
        auto ev_end = (LPOVERLAPPED_ENTRY)events_ + count;
        for (auto ev = ev_beg; ev != ev_end; ++ev) {
            // If channel is invalid, tracker should be removed.
            auto tracker = (channel_tracker_ptr)ev->lpOverlapped;
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