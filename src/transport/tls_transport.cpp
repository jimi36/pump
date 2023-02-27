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

#include "pump/memory.h"
#include "pump/transport/tls_transport.h"

namespace pump {
namespace transport {

tls_transport::tls_transport() noexcept
  : base_transport(transport_tls, nullptr, -1),
    last_send_iob_size_(0),
    last_send_iob_(nullptr),
    pending_opt_cnt_(0),
    sendlist_(32) {
}

tls_transport::~tls_transport() {
    __clear_send_pockets();
}

void tls_transport::init(
    flow::flow_tls_sptr &&flow,
    const address &local_address,
    const address &remote_address) {
    // Set local and remote address.
    local_address_ = local_address;
    remote_address_ = remote_address;

    flow_ = std::forward<flow::flow_tls_sptr>(flow);

    // Set channel fd
    poll::channel::__set_fd(flow_->get_fd());
}

error_code tls_transport::start(
    service *sv,
    read_mode mode,
    const transport_callbacks &cbs) {
    if (sv == nullptr) {
        pump_debug_log("service invalid");
        return error_invalid;
    }

    if (mode != read_mode_once &&
        mode != read_mode_loop) {
        pump_debug_log("read mode invalid");
        return error_invalid;
    }

    if (!cbs.read_cb ||
        !cbs.stopped_cb ||
        !cbs.disconnected_cb) {
        pump_debug_log("callbacks invalid");
        return error_invalid;
    }

    if (!flow_) {
        pump_debug_log("tls transport's flow invalid");
        return error_invalid;
    }

    if (!__set_state(state_none, state_starting)) {
        pump_debug_log("tls transport already started");
        return error_fault;
    }

    do {
        cbs_ = cbs;

        rmode_ = mode;

        __set_service(sv);

        if (!__install_read_tracker()) {
            pump_debug_log("install tls transport's read tracker failed");
            break;
        }
        if (!__install_send_tracker()) {
            pump_debug_log("install tcp transport's send tracker failed");
            break;
        }

        if (__set_state(state_starting, state_started)) {
            return error_none;
        }
    } while (false);

    __set_state(state_starting, state_error);

    return error_fault;
}

void tls_transport::stop() {
    while (is_started()) {
        // Change state from started to stopping.
        if (__set_state(state_started, state_stopping)) {
            // Wait pending opt count reduce to zero.
            while (pending_opt_cnt_.load(std::memory_order_relaxed) != 0) {
            }
            // If no data to send, shutdown transport flow and post channel
            // event, else shutdown transport flow read and wait finishing send.
            if (pending_send_size_.load(std::memory_order_acquire) == 0) {
                __shutdown_transport_flow(SHUT_RDWR);
                __post_channel_event(shared_from_this(), channel_event_disconnected);
            } else {
                __shutdown_transport_flow(SHUT_RD);
            }
            return;
        }
    }

    // If in disconnecting state at the moment, it means transport is
    // disconnected but hasn't triggered callback yet. So we just change
    // state to stopping, and then transport will trigger stopped callabck.
    __set_state(state_disconnecting, state_stopping);
}

void tls_transport::force_stop() {
    while (is_started()) {
        // Change state from started to stopping.
        if (__set_state(state_started, state_stopping)) {
            // Wait pending opt count reduce to zero.
            while (pending_opt_cnt_.load(std::memory_order_relaxed) != 0) {
            }
            // Shutdown transport flow and post channel event.
            __shutdown_transport_flow(SHUT_RDWR);
            __post_channel_event(shared_from_this(), channel_event_disconnected);
            return;
        }
    }

    // If in disconnecting state at the moment, it means transport is
    // disconnected but hasn't triggered callback yet. So we just change
    // state to stopping, and then transport will trigger stopped callabck.
    __set_state(state_disconnecting, state_stopping);
}

error_code tls_transport::async_read() {
    if (!is_started()) {
        pump_debug_log("tls transport not started");
        return error_unstart;
    }

    auto ec = error_none;
    pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
    if (rmode_ == read_mode_loop) {
        if (!__change_read_state(read_none, read_pending)) {
            pump_debug_log("tls transport's already reading by loop");
            ec = error_fault;
        } else if (!__start_read_tracker()) {
            pump_debug_log("start tls transport's read tracker failed");
            ec = error_fault;
        }
    } else {
        if (!__is_state(state_started)) {
            pump_debug_log("tls transport not started");
            ec = error_unstart;
        } else if (!__change_read_state(read_none, read_pending)) {
            pump_debug_log("tls transport's already reading");
            ec = error_fault;
        } else if (flow_->has_unread_data()) {
            __post_channel_event(
                shared_from_this(),
                channel_event_read,
                nullptr,
                read_pid);
        } else if (!__start_read_tracker()) {
            pump_debug_log("start tls transport's read tracker failed");
            ec = error_fault;
        }
    }
    pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

    return ec;
}

error_code tls_transport::send(const char *b, int32_t size) {
    if (b == nullptr || size <= 0) {
        pump_debug_log("buffer invalid");
        return error_invalid;
    }

    if (!is_started()) {
        pump_debug_log("tls transport not started");
        return error_unstart;
    }

    auto ec = error_none;
    pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
    do {
        if (pump_unlikely(!__is_state(state_started))) {
            pump_debug_log("tls transport is not started");
            ec = error_unstart;
            break;
        }

        auto iob = toolkit::io_buffer::create();
        if (iob == nullptr) {
            pump_debug_log("create iob object failed");
            ec = error_fault;
            break;
        }
        if (!iob->write(b, size)) {
            iob->unrefer();
            pump_debug_log("write to iob failed");
            ec = error_fault;
            break;
        }
        if (!__async_send(iob)) {
            pump_debug_log("tls transport async send failed");
            ec = error_fault;
        }
    } while (false);
    pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

    return ec;
}

error_code tls_transport::send(toolkit::io_buffer *iob) {
    if (iob == nullptr || iob->size() == 0) {
        pump_debug_log("iob invalid");
        return error_invalid;
    }

    if (!is_started()) {
        pump_debug_log("tls transport not started");
        return error_unstart;
    }

    auto ec = error_none;
    pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
    do {
        if (!__is_state(state_started)) {
            pump_debug_log("tls transport not started");
            ec = error_unstart;
            break;
        }

        iob->refer();
        if (!__async_send(iob)) {
            pump_debug_log("tls transport async send failed");
            ec = error_fault;
        }
    } while (false);
    pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

    return ec;
}

void tls_transport::on_channel_event(int32_t ev, void *arg) {
    switch (ev) {
    case channel_event_disconnected: {
        base_transport::on_channel_event(ev, arg);
        break;
    }
    case channel_event_buffer_sent: {
        auto iob = (toolkit::io_buffer *)arg;
        cbs_.sent_cb(iob);
        iob->unrefer();
        break;
    }
    case channel_event_read: {
        while (__is_state(state_starting, std::memory_order_relaxed)) {
            // pump_debug_log("tls transport starting, wait");
        }

        bool disconnected = false;
        char data[max_tcp_buffer_size];
        auto size = flow_->read(data, sizeof(data));
        if (size > 0) {
            if (rmode_ == read_mode_once) {
                // Change read state from read_pending to read_none.
                if (!__change_read_state(read_pending, read_none)) {
                    pump_debug_log("free tls transport's read state failed");
                    disconnected = true;
                }
            } else if (!__start_read_tracker()) {
                pump_debug_log("start tls transport's read tracker failed");
                disconnected = true;
            }
            // Callback read data.
            cbs_.read_cb(data, size);
        } else if (size < 0) {
            if (!__start_read_tracker()) {
                pump_debug_log("start tls transport's read tracker failed");
                disconnected = true;
            }
        } else {
            pump_debug_log("tls transport read zero size and already disconnected");
            disconnected = true;
        }

        if (disconnected) {
            __try_triggering_disconnected_callback();
        }
        break;
    }
    default:
        pump_abort_with_log("unknown channel event %d", ev);
    }
}

void tls_transport::on_read_event() {
    // Wait transport starting end
    while (__is_state(state_starting, std::memory_order_relaxed)) {
        // pump_debug_log("tls transport starting, wait");
    }

    bool disconnected = false;
    char data[max_tcp_buffer_size];
    auto size = flow_->read(data, sizeof(data));
    if (size > 0) {
        if (rmode_ == read_mode_once) {
            // Free read state.
            if (!__change_read_state(read_pending, read_none)) {
                pump_debug_log("free tls transport's read state failed");
                disconnected = true;
            }
        } else {
            if (!__start_read_tracker()) {
                pump_debug_log("start tls transport's read tracker failed");
                disconnected = true;
            }
        }
        // Callback data.
        cbs_.read_cb(data, size);
    } else if (size < 0) {
        if (!__start_read_tracker()) {
            pump_debug_log("start tls transport's read tracker failed");
            disconnected = true;
        }
    } else {
        pump_debug_log("tls transport read zero size and already disconnected");
        disconnected = true;
    }

    if (disconnected) {
        __try_triggering_disconnected_callback();
    }
}

void tls_transport::on_send_event() {
    if (pump_likely(last_send_iob_ != nullptr)) {
        switch (flow_->send()) {
        case error_none:
            __handle_sent_buffer();
            if (pending_send_size_.fetch_sub(last_send_iob_size_) > last_send_iob_size_) {
                goto continue_send;
            }
            goto end;
        case error_again:
            if (!__start_send_tracker()) {
                pump_debug_log("resume tls transport's send tracker failed");
                goto disconnected;
            }
            return;
        default:
            pump_debug_log("tls transport's flow send data failed");
            goto disconnected;
        }
    }

continue_send:
    switch (__send_once()) {
    case error_none:
        goto end;
    case error_again:
        if (!__start_send_tracker()) {
            pump_debug_log("start tls transport's send tracker failed");
            goto disconnected;
        }
        return;
    default:
        pump_debug_log("tls transport send once failed");
        goto disconnected;
    }

disconnected:
    if (__try_triggering_disconnected_callback()) {
        return;
    }

end:
    __trigger_stopped_callback();
}

void tls_transport::__shutdown_transport_flow(int32_t how) {
    if (flow_) {
        flow_->shutdown(how);
    }
}

void tls_transport::__close_transport_flow() {
    if (flow_) {
        flow_->close();
    }
}

bool tls_transport::__async_send(toolkit::io_buffer *iob) {
    // Insert buffer to sendlist.
    if (pump_unlikely(!sendlist_.push(iob))) {
        pump_abort_with_log("push iob to queue failed");
    }

    // If there are no more buffers, we should try to get next send chance.
    if (pending_send_size_.fetch_add(iob->size()) > 0) {
        return true;
    }

    switch (__send_once()) {
    case error_none:
        return true;
    case error_again:
        if (!__start_send_tracker()) {
            pump_debug_log("start tls transport's send tracker failed");
            break;
        }
        return true;
    default:
        pump_debug_log("tls transport send once failed");
        break;
    }

    if (__set_state(state_started, state_disconnecting)) {
        __post_channel_event(shared_from_this(), channel_event_disconnected);
    }

    return false;
}

int32_t tls_transport::__send_once() {
    // Pop next buffer from sendlist.
    pump_assert(last_send_iob_ == nullptr);
    if (pump_unlikely(!sendlist_.pop(last_send_iob_))) {
        pump_abort_with_log("pop iob from queue failed");
    }

    // Save last send buffer data size.
    last_send_iob_size_ = last_send_iob_->size();

    auto ret = flow_->want_to_send(last_send_iob_);
    if (pump_likely(ret == error_none)) {
        // Handle sent buffer.
        __handle_sent_buffer();
        // Reduce pending send size.
        if (pending_send_size_.fetch_sub(last_send_iob_size_) > last_send_iob_size_) {
            return error_again;
        }
        return error_none;
    } else if (ret == error_again) {
        return error_again;
    }

    return error_fault;
}

void tls_transport::__handle_sent_buffer() {
    if (cbs_.sent_cb) {
        __post_channel_event(
            shared_from_this(),
            channel_event_buffer_sent,
            last_send_iob_);
    } else {
        last_send_iob_->unrefer();
    }
    last_send_iob_ = nullptr;
}

void tls_transport::__clear_send_pockets() {
    if (last_send_iob_) {
        last_send_iob_->unrefer();
    }

    toolkit::io_buffer *iob;
    while (sendlist_.pop(iob)) {
        iob->unrefer();
    }
}

}  // namespace transport
}  // namespace pump
