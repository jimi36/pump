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
      : base_transport(UDP_TRANSPORT, nullptr, -1) {
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
        PUMP_DEBUG_FAILED(
            !__set_state(TRANSPORT_INITED, TRANSPORT_STARTING), 
            "udp_transport: start failed for transport state incorrect",
            return ERROR_INVALID);

        bool ret = false;
        toolkit::defer cleanup([&]() {
            if (ret) {
                __set_state(TRANSPORT_STARTING, TRANSPORT_STARTED);
            } else {
                __set_state(TRANSPORT_STARTING, TRANSPORT_ERROR);
                __close_transport_flow();
            }
        });

        PUMP_DEBUG_FAILED(
            sv == nullptr, 
            "udp_transport: start failed for service invalid",
            return ERROR_INVALID);
        __set_service(sv);

        PUMP_DEBUG_FAILED(
            mode != READ_MODE_ONCE && mode != READ_MODE_LOOP,
            "tcp_transport: start failed for transport state incorrect",
            return ERROR_INVALID);
        rmode_ = mode;

        PUMP_DEBUG_FAILED(
            !cbs.read_from_cb || !cbs.stopped_cb, 
            "udp_transport: start failed for callbacks invalid",
            return ERROR_INVALID);
        cbs_ = cbs;

        if (!__open_transport_flow()) {
            PUMP_DEBUG_LOG("udp_transport: start failed for opening flow failed");
            return ERROR_FAULT;
        }

        if (!__start_read_tracker()) {
            PUMP_DEBUG_LOG("udp_transport: start failed for starting tracker failed");
            return ERROR_FAULT;
        }

        ret = true;

        return ERROR_OK;
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

    error_code udp_transport::read_continue() {
        if (!is_started()) {
            PUMP_DEBUG_LOG("tcp_transport: read for once failed for not in started");
            return ERROR_UNSTART;
        }

        if (rmode_ != READ_MODE_ONCE || 
            !__change_read_state(READ_NONE, READ_PENDING) ||
            !__resume_read_tracker()) {
            return ERROR_FAULT;
        }

        return ERROR_OK;
    }

    error_code udp_transport::send(
        const block_t *b,
        int32_t size,
        const address &address) {
        PUMP_DEBUG_FAILED(
            b == nullptr || size <= 0, 
            "udp_transport: send failed for buffer invalid",
            return ERROR_INVALID);

        if (PUMP_UNLIKELY(!__is_state(TRANSPORT_STARTED))) {
            PUMP_DEBUG_LOG("udp_transport: send failed for not in statred");
            return ERROR_UNSTART;
        }

        if (flow_->send(b, size, address) < 0) {
            PUMP_DEBUG_LOG("udp_transport: send failed");
            return ERROR_AGAIN;
        }

        return ERROR_OK;
    }

    void udp_transport::on_read_event() {
        // If transport is in starting, resume read tracker.
        if (__is_state(TRANSPORT_STARTING, std::memory_order_relaxed)) {
            PUMP_DEBUG_LOG("udp_transport: handle read failed for starting");
            if (!__resume_read_tracker()) {
                PUMP_WARN_LOG("udp_transport: handle read failed for resuming tracker failed");
                return;
            }
        }

        address from_addr;
        block_t data[MAX_UDP_BUFFER_SIZE];
        int32_t size = flow_->read_from(data, sizeof(data), &from_addr);
        if (PUMP_LIKELY(size > 0)) {
            if (rmode_ == READ_MODE_ONCE) {
                // Change read state from READ_PENDING to READ_NONE.
                if (!__change_read_state(READ_PENDING, READ_NONE)) {
                    PUMP_WARN_LOG("udp_transport: handle read failed for changing read state");
                    return;
                }
            } else {
                // Resume read tracker to read next time.
                if (!__resume_read_tracker()) {
                    PUMP_WARN_LOG("udp_transport: handle read event failed for resuming tracker failed");
                    return;
                }
                // Callback read data.
                cbs_.read_cb(data, size);
            }
        } else {
            // Resume read tracker to read next time.
            if (!__resume_read_tracker()) {
                PUMP_WARN_LOG("udp_transport: handle read event failed for resuming tracker failed");
            }
        }
    }

    bool udp_transport::__open_transport_flow() {
        // Init udp transport flow.
        flow_.reset(
            object_create<flow::flow_udp>(), 
            object_delete<flow::flow_udp>);
        if (!flow_) {
            PUMP_WARN_LOG("udp_transport: open flow failed for creating flow failed");
            return false;
        }
        if (flow_->init(shared_from_this(), local_address_) != ERROR_OK) {
            PUMP_DEBUG_LOG("udp_transport: open flow failed for initing flow failed");
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
