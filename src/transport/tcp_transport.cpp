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
#include "pump/transport/tcp_transport.h"

namespace pump {
namespace transport {

tcp_transport::tcp_transport() noexcept
  : base_transport(transport_tcp, nullptr, -1),
    last_send_iob_size_(0),
    last_send_iob_(nullptr),
    pending_opt_cnt_(0),
    sendlist_(32) {
}

tcp_transport::~tcp_transport() {
    __clear_sendlist();
}

void tcp_transport::init(
    pump_socket fd,
    const address &local_address,
    const address &remote_address) {
    // Set addresses.
    local_address_ = local_address;
    remote_address_ = remote_address;
    // Set channel fd
    poll::channel::__set_fd(fd);
}

error_code tcp_transport::start(
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

    if (flow_) {
        pump_debug_log("tcp transport's flow already exists");
        return error_invalid;
    }

    if (!__set_state(state_none, state_starting)) {
        pump_debug_log("tcp transport already started");
        return error_fault;
    }

    do {
        cbs_ = cbs;

        rmode_ = mode;

        __set_service(sv);

        if (!__open_transport_flow()) {
            pump_debug_log("open tcp transport's flow failed");
            break;
        }

        if (!__install_read_tracker()) {
            pump_debug_log("install tcp transport's read tracker failed");
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

void tcp_transport::stop() {
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

void tcp_transport::force_stop() {
    while (is_started()) {
        // Change state from started to stopping.
        if (__set_state(state_started, state_stopping)) {
            // Wait pending opt count reduce to zero.
            while (pending_opt_cnt_.load(std::memory_order_relaxed) != 0) {
            }
            // Shutdown transport flow.
            __shutdown_transport_flow(SHUT_RDWR);
            // Post channel event.
            __post_channel_event(shared_from_this(), channel_event_disconnected);
            return;
        }
    }

    // If in disconnecting state at the moment, it means transport is
    // disconnected but hasn't triggered callback yet. So we just change
    // state to stopping, and then transport will trigger stopped callabck.
    __set_state(state_disconnecting, state_stopping);
}

error_code tcp_transport::async_read() {
    if (!is_started()) {
        pump_debug_log("tcp transport not started");
        return error_unstart;
    }

    auto ec = error_none;
    pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
    if (!__is_state(state_started)) {
        pump_debug_log("tcp transport not started");
        ec = error_unstart;
    } else if (rmode_ == read_mode_loop) {
        if (!__change_read_state(read_none, read_pending)) {
            pump_debug_log("tcp transport already reading by loop");
            ec = error_fault;
        } else if (!__start_read_tracker()) {
            pump_debug_log("start tcp transport's read tracker failed");
            ec = error_fault;
        }
    } else {
        if (!__change_read_state(read_none, read_pending)) {
            pump_debug_log("tcp transport already reading");
            ec = error_fault;
        } else if (!__start_read_tracker()) {
            pump_debug_log("start tcp transport's read tracker failed");
            ec = error_fault;
        }
    }
    pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

    return ec;
}

error_code tcp_transport::send(const char *b, int32_t size) {
    if (b == nullptr || size <= 0) {
        pump_debug_log("buffer is invalid");
        return error_invalid;
    }

    if (!is_started()) {
        pump_debug_log("tcp transport not started");
        return error_unstart;
    }

    auto ec = error_none;
    pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
    do {
        if (pump_unlikely(!__is_state(state_started))) {
            pump_debug_log("tls transport not started");
            ec = error_unstart;
            break;
        }

        auto iob = toolkit::io_buffer::create();
        if (iob == nullptr) {
            pump_warn_log("new iob object failed");
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
            pump_debug_log("tcp transport async send failed");
            ec = error_fault;
        }
    } while (false);
    pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

    return ec;
}

error_code tcp_transport::send(toolkit::io_buffer *iob) {
    if (iob == nullptr || iob->size() == 0) {
        pump_debug_log("iob is invalid");
        return error_invalid;
    }

    if (!is_started()) {
        pump_debug_log("tcp transport not started");
        return error_unstart;
    }

    auto ec = error_none;
    pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
    do {
        if (pump_unlikely(!__is_state(state_started))) {
            pump_debug_log("tcp transport not started");
            ec = error_unstart;
            break;
        }

        iob->refer();
        if (!__async_send(iob)) {
            pump_debug_log("tcp transport async send failed");
            ec = error_fault;
        }
    } while (false);
    pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

    return ec;
}

void tcp_transport::on_channel_event(int32_t ev, void *arg) {
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
    default:
        pump_abort_with_log("unknown channel event %d", ev);
    }
}

void tcp_transport::on_read_event() {
    // Wait transport starting end
    while (__is_state(state_starting, std::memory_order_relaxed)) {
        // pump_debug_log("tcp transport starting, wait");
    }

    bool disconnected = false;
    char data[max_tcp_buffer_size];
    auto size = flow_->read(data, max_tcp_buffer_size);
    if (size > 0) {
        if (rmode_ == read_mode_once) {
            // Free read state.
            if (!__change_read_state(read_pending, read_none)) {
                pump_debug_log("free tcp transport's read state failed");
                disconnected = true;
            }
        } else {
            if (!__start_read_tracker()) {
                pump_debug_log("start tcp transport's read tracker failed");
                disconnected = true;
            }
        }
        // Callback data.
        cbs_.read_cb(data, size);
    } else {
        pump_debug_log("tcp transport read zero size and already disconnected");
        disconnected = true;
    }

    if (disconnected) {
        __try_triggering_disconnected_callback();
    }
}

void tcp_transport::on_send_event() {
    if (last_send_iob_ != nullptr) {
        switch (flow_->send()) {
        case error_none:
            __handle_sent_buffer();
            if (pending_send_size_.fetch_sub(last_send_iob_size_) > last_send_iob_size_) {
                goto continue_send;
            }
            goto end;
        case error_again:
            if (!__start_send_tracker()) {
                pump_debug_log("start tcp transport's send tracker failed");
                goto disconnected;
            }
            return;
        default:
            pump_debug_log("tcp transport's flow send data failed");
            goto disconnected;
        }
    }

continue_send:
    switch (__send_once()) {
    case error_none:
        goto end;
    case error_again:
        if (!__start_send_tracker()) {
            pump_debug_log("start tcp transport's send tracker failed");
            goto disconnected;
        }
        return;
    default:
        pump_debug_log("tcp transport send once failed");
        goto disconnected;
    }

disconnected:
    if (__try_triggering_disconnected_callback()) {
        return;
    }

end:
    __trigger_stopped_callback();
}

bool tcp_transport::__open_transport_flow() {
    flow_.reset(
        pump_object_create<flow::flow_tcp>(),
        pump_object_destroy<flow::flow_tcp>);
    if (!flow_) {
        pump_warn_log("mew tcp transport's flow object failed");
        return false;
    } else if (!flow_->init(shared_from_this(), get_fd())) {
        pump_debug_log("init tcp transport's flow failed");
        net::close(get_fd());
        return false;
    }
    return true;
}

void tcp_transport::__shutdown_transport_flow(int32_t how) {
    if (flow_) {
        flow_->shutdown(how);
    }
}

void tcp_transport::__close_transport_flow() {
    if (flow_) {
        flow_->close();
    }
}

bool tcp_transport::__async_send(toolkit::io_buffer *iob) {
    // Push buffer to sendlist.
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
            pump_debug_log("start tcp transport's send tracker failed");
            break;
        }
        return true;
    default:
        pump_debug_log("tcp transport send once failed");
        break;
    }

    if (__set_state(state_started, state_disconnecting)) {
        __post_channel_event(shared_from_this(), channel_event_disconnected);
    }

    return false;
}

error_code tcp_transport::__send_once() {
    // Pop next buffer from sendlist to send.
    pump_assert(last_send_iob_ == nullptr);
    if (pump_unlikely(!sendlist_.pop(last_send_iob_))) {
        pump_abort_with_log("pop iob from queue failed");
    }

    // Save last send buffer data size.
    last_send_iob_size_ = last_send_iob_->size();

    // Try to send the buffer.
    auto ret = flow_->want_to_send(last_send_iob_);
    if (ret == error_none) {
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

void tcp_transport::__handle_sent_buffer() {
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

void tcp_transport::__clear_sendlist() {
    if (last_send_iob_ != nullptr) {
        last_send_iob_->unrefer();
    }

    toolkit::io_buffer *iob;
    while (sendlist_.pop(iob)) {
        iob->unrefer();
    }
}

}  // namespace transport
}  // namespace pump
