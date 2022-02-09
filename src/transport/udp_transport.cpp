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
    base_transport(UDP_TRANSPORT, nullptr, -1) {
    local_address_ = bind_address;
}

udp_transport::~udp_transport() {
    __stop_read_tracker();
    __stop_send_tracker();
}

error_code udp_transport::start(service *sv,
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

    if (!cbs.read_from_cb || !cbs.stopped_cb) {
        PUMP_WARN_LOG("callbacks is invalid");
        return ERROR_INVALID;
    }

    if (!__set_state(TRANSPORT_INITED, TRANSPORT_STARTING)) {
        PUMP_WARN_LOG("udp transport is already started before");
        return ERROR_FAULT;
    }

    do {
        cbs_ = cbs;

        rmode_ = mode;

        __set_service(sv);

        if (!__open_transport_flow()) {
            PUMP_WARN_LOG("open udp transport's flow failed");
            break;
        }

        if (!__start_read_tracker()) {
            PUMP_WARN_LOG("start udp transport's read tracker failed");
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

void udp_transport::stop() {
    while (__is_state(TRANSPORT_STARTED)) {
        // Change state from started to stopping.
        if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
            // Shutdown transport flow.
            __shutdown_transport_flow(SHUT_RDWR);
            // Post channel event.
            __post_channel_event(shared_from_this(), 0);
            return;
        }
    }
}

error_code udp_transport::continue_read() {
    if (!is_started()) {
        PUMP_WARN_LOG("udp transport is not started");
        return ERROR_UNSTART;
    }

    if (rmode_ != READ_MODE_ONCE || !__change_read_state(READ_NONE, READ_PENDING) ||
        !__resume_read_tracker()) {
        return ERROR_FAULT;
    }

    return ERROR_OK;
}

error_code udp_transport::send(const block_t *b, int32_t size, const address &address) {
    if (b == nullptr || size <= 0) {
        PUMP_WARN_LOG("sent buffer is invalid");
        return ERROR_INVALID;
    }

    if (PUMP_UNLIKELY(!__is_state(TRANSPORT_STARTED))) {
        PUMP_WARN_LOG("udp transport is not started");
        return ERROR_UNSTART;
    }

    if (flow_->send(b, size, address) < 0) {
        PUMP_WARN_LOG("udp transport's flow send failed");
        return ERROR_AGAIN;
    }

    return ERROR_OK;
}

void udp_transport::on_read_event() {
    // If transport is in starting, resume read tracker.
    if (__is_state(TRANSPORT_STARTING, std::memory_order_relaxed)) {
        PUMP_DEBUG_LOG("udp transport is starting, delay to handle read event");
        if (!__resume_read_tracker()) {
            PUMP_WARN_LOG("resume udp transport's read tracker failed");
            return;
        }
    }

    address remote_addr;
    block_t data[MAX_UDP_BUFFER_SIZE];
    int32_t size = flow_->read_from(data, sizeof(data), &remote_addr);
    if (PUMP_LIKELY(size > 0)) {
        if (rmode_ == READ_MODE_ONCE) {
            // Change read state from READ_PENDING to READ_NONE.
            if (!__change_read_state(READ_PENDING, READ_NONE)) {
                PUMP_WARN_LOG(
                    "change udp transport's read state from pending to none failed");
            }
        } else if (!__resume_read_tracker()) {
            PUMP_WARN_LOG("resume udp transport's read tracker failed");
        }
        // Callback read data.
        cbs_.read_from_cb(data, size, remote_addr);
    } else if (!__resume_read_tracker()) {
        PUMP_WARN_LOG("resume udp transport's read tracker failed");
    }
}

bool udp_transport::__open_transport_flow() {
    // Init udp transport flow.
    flow_.reset(object_create<flow::flow_udp>(), object_delete<flow::flow_udp>);
    if (!flow_) {
        PUMP_WARN_LOG("mew udp transport's flow object failed");
        return false;
    }
    if (flow_->init(shared_from_this(), local_address_) != ERROR_OK) {
        PUMP_WARN_LOG("init udp transport's flow failed");
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
