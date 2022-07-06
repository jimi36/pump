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

#define AFD_POLL_RECEIVE_BIT 0
#define AFD_POLL_RECEIVE (1 << AFD_POLL_RECEIVE_BIT)
#define AFD_POLL_RECEIVE_EXPEDITED_BIT 1
#define AFD_POLL_RECEIVE_EXPEDITED (1 << AFD_POLL_RECEIVE_EXPEDITED_BIT)
#define AFD_POLL_SEND_BIT 2
#define AFD_POLL_SEND (1 << AFD_POLL_SEND_BIT)
#define AFD_POLL_DISCONNECT_BIT 3
#define AFD_POLL_DISCONNECT (1 << AFD_POLL_DISCONNECT_BIT)
#define AFD_POLL_ABORT_BIT 4
#define AFD_POLL_ABORT (1 << AFD_POLL_ABORT_BIT)
#define AFD_POLL_LOCAL_CLOSE_BIT 5
#define AFD_POLL_LOCAL_CLOSE (1 << AFD_POLL_LOCAL_CLOSE_BIT)
#define AFD_POLL_CONNECT_BIT 6
#define AFD_POLL_CONNECT (1 << AFD_POLL_CONNECT_BIT)
#define AFD_POLL_ACCEPT_BIT 7
#define AFD_POLL_ACCEPT (1 << AFD_POLL_ACCEPT_BIT)
#define AFD_POLL_CONNECT_FAIL_BIT 8
#define AFD_POLL_CONNECT_FAIL (1 << AFD_POLL_CONNECT_FAIL_BIT)
#define AFD_POLL_QOS_BIT 9
#define AFD_POLL_QOS (1 << AFD_POLL_QOS_BIT)
#define AFD_POLL_GROUP_QOS_BIT 10
#define AFD_POLL_GROUP_QOS (1 << AFD_POLL_GROUP_QOS_BIT)

#define AFD_NUM_POLL_EVENTS 11
#define AFD_POLL_ALL ((1 << AFD_NUM_POLL_EVENTS) - 1)

#define AFD_RECEIVE 5
#define AFD_RECEIVE_DATAGRAM 6
#define AFD_POLL 9

#define FSCTL_AFD_BASE FILE_DEVICE_NETWORK
#define _AFD_CONTROL_CODE(operation, method) \
    ((FSCTL_AFD_BASE) << 12 | (operation << 2) | method)

#define IOCTL_AFD_RECEIVE _AFD_CONTROL_CODE(AFD_RECEIVE, METHOD_NEITHER)
#define IOCTL_AFD_RECEIVE_DATAGRAM \
    _AFD_CONTROL_CODE(AFD_RECEIVE_DATAGRAM, METHOD_NEITHER)
#define IOCTL_AFD_POLL _AFD_CONTROL_CODE(AFD_POLL, METHOD_BUFFERED)

#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001UL
#endif

namespace pump {
namespace poll {

#if defined(PUMP_HAVE_IOCP)
const static uint32_t AL_NONE_EVENT = 0;
const static uint32_t AL_READ_EVENT =
    AFD_POLL_ACCEPT | AFD_POLL_RECEIVE | AFD_POLL_RECEIVE_EXPEDITED |
    AFD_POLL_LOCAL_CLOSE | AFD_POLL_DISCONNECT | AFD_POLL_ABORT;
const static uint32_t AL_SEND_EVENT =
    AFD_POLL_SEND | AFD_POLL_DISCONNECT | AFD_POLL_CONNECT_FAIL;
const static uint32_t AL_ERR_EVENT = AFD_POLL_ABORT | AFD_POLL_CONNECT_FAIL;

#define RTL_CONSTANT_STRING(s) \
    { sizeof(s) - sizeof((s)[0]), sizeof(s), (PWSTR)s }
static UNICODE_STRING afd__device_name =
    RTL_CONSTANT_STRING(L"\\Device\\Afd\\Poller");
#undef RTL_CONSTANT_STRING

#define RTL_CONSTANT_OBJECT_ATTRIBUTES(ObjectName, Attributes) \
    { sizeof(OBJECT_ATTRIBUTES), NULL, ObjectName, Attributes, NULL, NULL }
static OBJECT_ATTRIBUTES afd__device_attributes =
    RTL_CONSTANT_OBJECT_ATTRIBUTES(&afd__device_name, 0);
#undef RTL_CONSTANT_OBJECT_ATTRIBUTES

HANDLE afd_create_device_handle(HANDLE iocp_handle) {
    /*
     * By opening \Device\Afd without specifying any extended attributes, we'll
     * get a handle that lets us talk to the AFD driver, but that doesn't have
     * an associated endpoint (so it's not a socket).
     */
    IO_STATUS_BLOCK iosb;
    HANDLE afd_device_handle;
    NTSTATUS status = NtCreateFile(
        &afd_device_handle,
        SYNCHRONIZE,
        &afd__device_attributes,
        &iosb,
        nullptr,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        0,
        nullptr,
        0);
    if (status != STATUS_SUCCESS) {
        pump_abort_with_log("afd_create_device_handle: create NT file failed");
    }

    if (CreateIoCompletionPort(
            afd_device_handle,
            iocp_handle,
            0,
            0) == nullptr ||
        SetFileCompletionNotificationModes(
            afd_device_handle,
            FILE_SKIP_SET_EVENT_ON_HANDLE) == FALSE) {
        pump_abort_with_log("afd_create_device_handle: NT file bind iocp handle failed")
    }

    return afd_device_handle;
}
#endif

afd_poller::afd_poller() noexcept :
    iocp_handler_(nullptr),
    afd_device_handler_(nullptr),
    events_(nullptr),
    max_event_count_(1024),
    cur_event_count_(0) {
#if defined(PUMP_HAVE_IOCP)
    iocp_handler_ = CreateIoCompletionPort(
        INVALID_HANDLE_VALUE,
        nullptr,
        0,
        0);
    if (iocp_handler_ == nullptr) {
        pump_err_log("create iocp headler failed");
        pump_abort();
    }

    afd_device_handler_ = afd_create_device_handle(iocp_handler_);
    if (afd_device_handler_ == nullptr) {
        pump_err_log("create afd device headler failed");
        pump_abort();
    }

    events_ = pump_malloc(sizeof(OVERLAPPED_ENTRY) * max_event_count_);
    if (events_ == nullptr) {
        pump_err_log("allocate afd events memory failed");
        pump_abort();
    }
#else
    pump_abort();
#endif
}

afd_poller::~afd_poller() {
#if defined(PUMP_HAVE_IOCP)
    if (afd_device_handler_ != nullptr) {
        CloseHandle(afd_device_handler_);
    }
    if (iocp_handler_ != nullptr) {
        CloseHandle(iocp_handler_);
    }
#endif
}

bool afd_poller::__install_channel_tracker(channel_tracker *tracker) {
#if defined(PUMP_HAVE_IOCP)
    if (__resume_channel_tracker(tracker)) {
        cur_event_count_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
#endif
    pump_warn_log("install channel tracker failed %d", net::last_errno());
    return false;
}

bool afd_poller::__uninstall_channel_tracker(channel_tracker *tracker) {
#if defined(PUMP_HAVE_IOCP)
    auto event = tracker->get_event();
    if (event->iosb.Status != STATUS_PENDING) {
        cur_event_count_.fetch_sub(1, std::memory_order_relaxed);
        return true;
    }

    IO_STATUS_BLOCK cancel_iosb;
    NTSTATUS cancel_status = NtCancelIoFileEx(
        afd_device_handler_,
        &(event->iosb),
        &cancel_iosb);
    if (cancel_status == STATUS_SUCCESS ||
        cancel_status == STATUS_NOT_FOUND) {
        cur_event_count_.fetch_sub(1, std::memory_order_relaxed);
        return true;
    }
#endif
    pump_warn_log("uninstall channel tracker failed %d", net::last_errno());
    return false;
}

bool afd_poller::__resume_channel_tracker(channel_tracker *tracker) {
#if defined(PUMP_HAVE_IOCP)
    auto expected_event = tracker->get_expected_event();
    auto event = tracker->get_event();
    event->info.Timeout.QuadPart = INT64_MAX;
    event->info.Exclusive = FALSE;
    event->info.NumberOfHandles = 1;
    event->info.Handles[0].Status = 0;
    event->info.Handles[0].Handle = (HANDLE)tracker->get_fd();
    if (expected_event & io_read) {
        event->info.Handles[0].Events = AL_READ_EVENT;
    } else if (expected_event & io_send) {
        event->info.Handles[0].Events = AL_SEND_EVENT;
    }
    event->iosb.Status = STATUS_PENDING;

    NTSTATUS status = NtDeviceIoControlFile(
        afd_device_handler_,
        nullptr,
        nullptr,
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
#endif
    pump_warn_log("resume channel tracker fialed %d", net::last_errno());
    return false;
}

void afd_poller::__poll(int32_t timeout) {
#if defined(PUMP_HAVE_IOCP)
    auto cur_event_count = cur_event_count_.load(std::memory_order_relaxed);
    if (pump_unlikely(cur_event_count > max_event_count_)) {
        max_event_count_ = cur_event_count;
        events_ = pump_realloc(events_, sizeof(OVERLAPPED_ENTRY) * max_event_count_);
        if (events_ == nullptr) {
            pump_err_log("reallocate afd events memory failed");
            pump_abort();
        }
    }

    DWORD completion_count = 0;
    LPOVERLAPPED_ENTRY iocp_events = (LPOVERLAPPED_ENTRY)events_;
    if (GetQueuedCompletionStatusEx(
            iocp_handler_,
            iocp_events,
            max_event_count_,
            &completion_count,
            timeout,
            FALSE) == FALSE) {
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
        auto tracker = (channel_tracker *)ev->lpOverlapped;
        if (tracker->untrack()) {
            auto ch = tracker->get_channel();
            if (ch) {
                ch->handle_io_event(tracker->get_expected_event());
            }
        }
    }
#endif
}
}  // namespace poll
}  // namespace pump