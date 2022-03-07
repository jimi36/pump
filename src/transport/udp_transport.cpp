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

#include "pump/transport/udp_transport.h"

namespace pump {
namespace transport {

udp_transport::udp_transport(const address &bind_address) noexcept :
    base_transport(transport_udp, nullptr, -1) {
    local_address_ = bind_address;
}

udp_transport::~udp_transport() {
    __stop_read_tracker();
    __stop_send_tracker();
}

error_code udp_transport::start(
    service *sv,
    read_mode mode,
    const transport_callbacks &cbs) {
    if (sv == nullptr) {
        pump_warn_log("service is invalid");
        return error_invalid;
    }

    if (mode != read_mode_once && mode != read_mode_loop) {
        pump_warn_log("read mode is invalid");
        return error_invalid;
    }

    if (!cbs.read_from_cb || !cbs.stopped_cb) {
        pump_warn_log("callbacks is invalid");
        return error_invalid;
    }

    if (!__set_state(state_none, state_starting)) {
        pump_warn_log("udp transport is already started before");
        return error_fault;
    }

    do {
        cbs_ = cbs;

        rmode_ = mode;

        __set_service(sv);

        if (!__open_transport_flow()) {
            pump_warn_log("open udp transport's flow failed");
            break;
        }

        if (!__start_read_tracker()) {
            pump_warn_log("start udp transport's read tracker failed");
            break;
        }

        if (__set_state(state_starting, state_started)) {
            return error_none;
        }
    } while (false);

    __set_state(state_starting, state_error);
    __close_transport_flow();

    return error_fault;
}

void udp_transport::stop() {
    while (__is_state(state_started)) {
        // Change state from started to stopping.
        if (__set_state(state_started, state_stopping)) {
            // Shutdown transport flow.
            __shutdown_transport_flow(SHUT_RDWR);
            // Post channel event.
            __post_channel_event(shared_from_this(), channel_event_disconnected);
            return;
        }
    }
}

error_code udp_transport::continue_read() {
    if (!is_started()) {
        pump_warn_log("udp transport is not started");
        return error_unstart;
    }

    if (rmode_ != read_mode_once ||
        !__change_read_state(read_none, read_pending) ||
        !__resume_read_tracker()) {
        return error_fault;
    }

    return error_none;
}

error_code udp_transport::send(
    const char *b,
    int32_t size,
    const address &address) {
    if (b == nullptr || size <= 0) {
        pump_warn_log("sent buffer is invalid");
        return error_invalid;
    }

    if (!is_started()) {
        pump_warn_log("udp transport is not started");
        return error_unstart;
    }

    if (flow_->send(b, size, address) < 0) {
        pump_warn_log("udp transport's flow send failed");
        return error_again;
    }

    return error_none;
}

void udp_transport::on_read_event() {
    // If transport is in starting, resume read tracker.
    if (__is_state(state_starting, std::memory_order_relaxed)) {
        pump_debug_log("udp transport is starting, delay to handle read event");
        if (!__resume_read_tracker()) {
            pump_warn_log("resume udp transport's read tracker failed");
            return;
        }
    }

    address remote_addr;
    char data[max_udp_buffer_size];
    int32_t size = flow_->read_from(data, sizeof(data), &remote_addr);
    if (pump_likely(size > 0)) {
        if (rmode_ == read_mode_once) {
            // Change read state from read_pending to read_none.
            if (!__change_read_state(read_pending, read_none)) {
                pump_warn_log("change udp transport's read state from pending to none failed");
            }
        } else if (!__resume_read_tracker()) {
            pump_warn_log("resume udp transport's read tracker failed");
        }
        // Callback read data.
        cbs_.read_from_cb(data, size, remote_addr);
    } else if (!__resume_read_tracker()) {
        pump_warn_log("resume udp transport's read tracker failed");
    }
}

bool udp_transport::__open_transport_flow() {
    // Init udp transport flow.
    flow_.reset(object_create<flow::flow_udp>(), object_delete<flow::flow_udp>);
    if (!flow_) {
        pump_warn_log("mew udp transport's flow object failed");
        return false;
    }
    if (flow_->init(shared_from_this(), local_address_) != error_none) {
        pump_warn_log("init udp transport's flow failed");
        return false;
    }

    // Set channel fd.
    poll::channel::__set_fd(flow_->get_fd());

    return true;
}

void udp_transport::__shutdown_transport_flow(int32_t how) {
    if (flow_) {
        flow_->shutdown(how);
    }
}

void udp_transport::__close_transport_flow() {
    if (flow_) {
        flow_->close();
    }
}

}  // namespace transport
}  // namespace pump
