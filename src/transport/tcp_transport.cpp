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

tcp_transport::tcp_transport() noexcept :
    base_transport(TCP_TRANSPORT, nullptr, -1),
    last_send_iob_size_(0),
    last_send_iob_(nullptr),
    pending_opt_cnt_(0),
    sendlist_(32) {}

tcp_transport::~tcp_transport() {
    __stop_read_tracker();
    __stop_send_tracker();
    __clear_sendlist();
}

void tcp_transport::init(pump_socket fd,
                         const address &local_address,
                         const address &remote_address) {
    // Set addresses.
    local_address_ = local_address;
    remote_address_ = remote_address;
    // Set channel fd
    poll::channel::__set_fd(fd);
}

error_code tcp_transport::start(service *sv,
                                read_mode mode,
                                const transport_callbacks &cbs) {
    if (sv == nullptr) {
        PUMP_WARN_LOG("service is invalid");
        return ERROR_INVALID;
    }

    if (mode != READ_MODE_ONCE && mode != READ_MODE_LOOP) {
        PUMP_WARN_LOG("read mode is invalid");
        return ERROR_INVALID;
    }

    if (!cbs.read_cb || !cbs.disconnected_cb || !cbs.stopped_cb) {
        PUMP_WARN_LOG("callbacks is invalid");
        return ERROR_INVALID;
    }

    if (flow_) {
        PUMP_WARN_LOG("tcp transport's flow is already exists");
        return ERROR_INVALID;
    }

    if (!__set_state(TRANSPORT_INITED, TRANSPORT_STARTING)) {
        PUMP_WARN_LOG("tcp transport is already started before");
        return ERROR_FAULT;
    }

    do {
        cbs_ = cbs;

        rmode_ = mode;

        __set_service(sv);

        if (!__open_transport_flow()) {
            PUMP_WARN_LOG("open tcp transport's flow failed");
            break;
        }

        if (!__change_read_state(READ_NONE, READ_PENDING)) {
            PUMP_WARN_LOG("change tcp transport's read state failed");
            break;
        }

        if (!__start_read_tracker()) {
            PUMP_WARN_LOG("start tcp transport's read tracker failed");
            break;
        }

        if (__set_state(TRANSPORT_STARTING, TRANSPORT_STARTED)) {
            return ERROR_OK;
        }
    } while (false);

    __set_state(TRANSPORT_STARTING, TRANSPORT_ERROR);
    __close_transport_flow();

    return ERROR_FAULT;
}

void tcp_transport::stop() {
    while (is_started()) {
        // Change state from started to stopping.
        if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
            // Wait pending opt count reduce to zero.
            while (pending_opt_cnt_.load(std::memory_order_relaxed) != 0)
                ;
            // If no data to send, shutdown transport flow and post channel
            // event, else shutdown transport flow read and wait finishing send.
            if (pending_send_size_.load(std::memory_order_acquire) == 0) {
                __shutdown_transport_flow(SHUT_RDWR);
                __post_channel_event(shared_from_this(), 0);
            } else {
                __shutdown_transport_flow(SHUT_RD);
            }
            return;
        }
    }

    // If in disconnecting state at the moment, it means transport is
    // disconnected but hasn't triggered callback yet. So we just change
    // state to stopping, and then transport will trigger stopped callabck.
    __set_state(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING);
}

void tcp_transport::force_stop() {
    while (is_started()) {
        // Change state from started to stopping.
        if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
            // Wait pending opt count reduce to zero.
            while (pending_opt_cnt_.load(std::memory_order_relaxed) != 0)
                ;
            // Shutdown transport flow.
            __shutdown_transport_flow(SHUT_RDWR);
            // Post channel event.
            __post_channel_event(shared_from_this(), 0);
            return;
        }
    }

    // If in disconnecting state at the moment, it means transport is
    // disconnected but hasn't triggered callback yet. So we just change
    // state to stopping, and then transport will trigger stopped callabck.
    __set_state(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING);
}

error_code tcp_transport::continue_read() {
    if (!is_started()) {
        PUMP_WARN_LOG("tcp transport is not started");
        return ERROR_UNSTART;
    }

    if (rmode_ != READ_MODE_ONCE) {
        return ERROR_FAULT;
    }

    error_code ec = ERROR_OK;
    pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
    do {
        if (pump_unlikely(!__is_state(TRANSPORT_STARTED))) {
            PUMP_WARN_LOG("tcp transport is not started");
            ec = ERROR_UNSTART;
            break;
        }
        if (!__change_read_state(READ_NONE, READ_PENDING)) {
            break;
        }
        if (!__resume_read_tracker()) {
            PUMP_WARN_LOG("resume tcp transport's read tracker failed");
            ec = ERROR_FAULT;
            break;
        }
    } while (false);
    pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

    return ec;
}

error_code tcp_transport::send(const char *b, int32_t size) {
    if (b == nullptr || size <= 0) {
        PUMP_WARN_LOG("sent buffer is invalid");
        return ERROR_INVALID;
    }

    if (!is_started()) {
        PUMP_WARN_LOG("tcp transport is not started");
        return ERROR_UNSTART;
    }

    error_code ec = ERROR_OK;
    pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
    do {
        if (pump_unlikely(!__is_state(TRANSPORT_STARTED))) {
            PUMP_WARN_LOG("tcp transport is not started");
            ec = ERROR_UNSTART;
            break;
        }

        auto iob = toolkit::io_buffer::create();
        if (pump_unlikely(iob == nullptr || !iob->write(b, size))) {
            PUMP_WARN_LOG("create or write data to io buffer failed");
            if (iob) {
                iob->unrefer();
            }
            ec = ERROR_FAULT;
            break;
        }

        if (!__async_send(iob)) {
            PUMP_WARN_LOG("tcp transport async send failed");
            ec = ERROR_FAULT;
        }
    } while (false);
    pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

    return ec;
}

error_code tcp_transport::send(toolkit::io_buffer *iob) {
    if (iob == nullptr || iob->size() == 0) {
        PUMP_WARN_LOG("sent io buffer is invalid");
        return ERROR_INVALID;
    }

    if (!is_started()) {
        PUMP_WARN_LOG("tcp transport is not started");
        return ERROR_UNSTART;
    }

    error_code ec = ERROR_OK;
    pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
    do {
        if (pump_unlikely(!__is_state(TRANSPORT_STARTED))) {
            PUMP_WARN_LOG("tcp transport is not started");
            ec = ERROR_UNSTART;
            break;
        }

        iob->refer();
        if (!__async_send(iob)) {
            PUMP_WARN_LOG("tcp transport async send failed");
            ec = ERROR_FAULT;
        }
    } while (false);
    pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

    return ec;
}

void tcp_transport::on_read_event() {
    // If transport is starting, resume read tracker.
    if (__is_state(TRANSPORT_STARTING, std::memory_order_relaxed)) {
        PUMP_DEBUG_LOG("tcp transport is starting, delay to handle read event");
        if (!__resume_read_tracker()) {
            PUMP_WARN_LOG("resume tcp transport's read tracker failed");
            __try_triggering_disconnected_callback();
            return;
        }
    }

    bool disconnected = false;
    char data[MAX_TCP_BUFFER_SIZE];
    int32_t size = flow_->read(data, MAX_TCP_BUFFER_SIZE);
    if (pump_likely(size > 0)) {
        if (rmode_ == READ_MODE_ONCE) {
            // Change read state from READ_PENDING to READ_NONE.
            if (!__change_read_state(READ_PENDING, READ_NONE)) {
                PUMP_WARN_LOG("change tcp transport's read state from pending "
                              "to none failed");
                disconnected = true;
            }
        } else if (!__resume_read_tracker()) {
            PUMP_WARN_LOG("resume tcp transport's read tracker failed");
            disconnected = true;
        }
        // Callback read data.
        cbs_.read_cb(data, size);
    } else {
        PUMP_WARN_LOG("tcp transport read zero size and already disconnected");
        disconnected = true;
    }

    if (disconnected) {
        __try_triggering_disconnected_callback();
    }
}

void tcp_transport::on_send_event() {
    if (last_send_iob_ != nullptr) {
        switch (flow_->send()) {
        case ERROR_OK:
            __reset_last_sent_iobuffer();
            if (pending_send_size_.fetch_sub(last_send_iob_size_) >
                last_send_iob_size_) {
                goto continue_send;
            }
            goto end;
        case ERROR_AGAIN:
            if (!__resume_send_tracker()) {
                PUMP_WARN_LOG("resume tcp transport's send tracker failed");
                goto disconnected;
            }
            return;
        default:
            PUMP_WARN_LOG("tcp transport's flow send data failed");
            goto disconnected;
        }
    }

continue_send:
    switch (__send_once()) {
    case ERROR_OK:
        goto end;
    case ERROR_AGAIN:
        if (!__resume_send_tracker()) {
            PUMP_WARN_LOG("resume tcp transport's send tracker failed");
            goto disconnected;
        }
        return;
    default:
        PUMP_WARN_LOG("tcp transport send once failed");
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
    // Init tcp transport flow.
    flow_.reset(object_create<flow::flow_tcp>(), object_delete<flow::flow_tcp>);
    if (!flow_) {
        PUMP_WARN_LOG("mew tcp transport's flow object failed");
        return false;
    }
    if (flow_->init(shared_from_this(), get_fd()) != ERROR_OK) {
        PUMP_WARN_LOG("init tcp transport's flow failed");
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
    PUMP_ABORT_WITH_LOG(!sendlist_.push(iob), "push io buffer to queue failed");

    // If there are no more buffers, we should try to get next send chance.
    if (pending_send_size_.fetch_add(iob->size()) > 0) {
        return true;
    }

    switch (__send_once()) {
    case ERROR_OK:
        return true;
    case ERROR_AGAIN:
        if (!__start_send_tracker()) {
            PUMP_WARN_LOG("start tcp transport's send tracker failed");
            break;
        }
        return true;
    default:
        PUMP_WARN_LOG("tcp transport send once failed");
        break;
    }

    if (__set_state(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING)) {
        __post_channel_event(shared_from_this(), 0);
    }

    return false;
}

error_code tcp_transport::__send_once() {
    PUMP_ASSERT(!last_send_iob_);
    // Pop next buffer from sendlist to send.
    PUMP_ABORT_WITH_LOG(!sendlist_.pop(last_send_iob_),
                        "pop io buffer from queue failed");
    // Save last send buffer data size.
    last_send_iob_size_ = last_send_iob_->size();

    // Try to send the buffer.
    auto ret = flow_->want_to_send(last_send_iob_);
    if (pump_likely(ret == ERROR_OK)) {
        // Reset last sent buffer.
        __reset_last_sent_iobuffer();
        // Reduce pending send size.
        if (pending_send_size_.fetch_sub(last_send_iob_size_) >
            last_send_iob_size_) {
            return ERROR_AGAIN;
        }
        return ERROR_OK;
    } else if (ret == ERROR_AGAIN) {
        return ERROR_AGAIN;
    }

    return ERROR_FAULT;
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
