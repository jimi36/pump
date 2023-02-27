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

udp_transport::udp_transport(const address &bind_address) noexcept
  : base_transport(transport_udp, nullptr, -1) {
    local_address_ = bind_address;
}

error_code udp_transport::start(
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

    if (!cbs.read_from_cb || !cbs.stopped_cb) {
        pump_debug_log("callbacks invalid");
        return error_invalid;
    }

    if (!__set_state(state_none, state_starting)) {
        pump_debug_log("udp transport already started");
        return error_fault;
    }

    do {
        cbs_ = cbs;

        rmode_ = mode;

        __set_service(sv);

        if (!__open_transport_flow()) {
            pump_debug_log("open udp transport's flow failed");
            break;
        }

        if (!__install_read_tracker()) {
            pump_debug_log("install udp transport's read tracker failed");
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

error_code udp_transport::async_read() {
    if (!is_started()) {
        pump_debug_log("udp transport not started");
        return error_unstart;
    }

    auto ec = error_none;
    if (rmode_ == read_mode_loop) {
        if (!__change_read_state(read_none, read_pending)) {
            pump_debug_log("udp transport already reading by loop");
            ec = error_fault;
        }
        if (!__start_read_tracker()) {
            pump_debug_log("start udp transport's read tracker failed");
            ec = error_fault;
        }
    } else {
        do {
            if (!__change_read_state(read_none, read_pending)) {
                pump_debug_log("udp transport already reading");
                ec = error_fault;
                break;
            }
            if (!__start_read_tracker()) {
                pump_debug_log("start udp transport's read tracker failed");
                ec = error_fault;
                break;
            }
        } while (false);
    }

    return ec;
}

error_code udp_transport::send(
    const char *b,
    int32_t size,
    const address &address) {
    if (b == nullptr || size <= 0) {
        pump_debug_log("buffer invalid");
        return error_invalid;
    }

    if (!is_started()) {
        pump_debug_log("udp transport not started");
        return error_unstart;
    }

    if (flow_->send(b, size, address) < 0) {
        pump_debug_log("udp transport's flow send failed");
        return error_again;
    }

    return error_none;
}

void udp_transport::on_read_event() {
    // Wait transport starting end.
    while (__is_state(state_starting, std::memory_order_relaxed)) {
        pump_debug_log("udp transport starting, wait");
    }

    address remote_addr;
    char data[max_udp_buffer_size];
    int32_t size = flow_->read_from(data, sizeof(data), &remote_addr);
    if (size > 0) {
        if (rmode_ == read_mode_once) {
            // Free read state.
            if (!__change_read_state(read_pending, read_none)) {
                pump_debug_log("free udp transport's read state failed");
            }
        } else if (!__start_read_tracker()) {
            pump_debug_log("start udp transport's read tracker failed");
        }
        // Callback read data.
        cbs_.read_from_cb(data, size, remote_addr);
    } else if (!__start_read_tracker()) {
        pump_debug_log("start udp transport's read tracker failed");
    }
}

bool udp_transport::__open_transport_flow() {
    // Init udp transport flow.
    flow_.reset(pump_object_create<flow::flow_udp>(), pump_object_destroy<flow::flow_udp>);
    if (!flow_) {
        pump_debug_log("mew udp transport's flow object failed");
        return false;
    }
    if (!flow_->init(shared_from_this(), local_address_)) {
        pump_debug_log("init udp transport's flow failed");
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
