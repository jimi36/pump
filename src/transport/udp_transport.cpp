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

    transport_error udp_transport::start(
        service_ptr sv,
        const transport_callbacks &cbs) {
        if (!sv) {
            PUMP_ERR_LOG("udp_transport: start failed with invalid service");
            return ERROR_INVALID;
        }

        if (!cbs.read_from_cb || !cbs.stopped_cb) {
            PUMP_ERR_LOG("udp_transport: start failed with invalid callbacks");
            return ERROR_INVALID;
        }

        if (!__set_status(TRANSPORT_INITED, TRANSPORT_STARTING)) {
            PUMP_ERR_LOG("udp_transport: start failed with wrong status");
            return ERROR_INVALID;
        }

        // Set callbacks
        cbs_ = cbs;

        // Set service
        __set_service(sv);

        toolkit::defer cleanup([&]() {
            __close_transport_flow();
            __set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
        });

        if (!__open_transport_flow()) {
            PUMP_ERR_LOG("udp_transport: start failed for opening flow failed");
            return ERROR_FAULT;
        }

        __set_status(TRANSPORT_STARTING, TRANSPORT_STARTED);

        cleanup.clear();

        return ERROR_OK;
    }

    void udp_transport::stop() {
        while (__is_status(TRANSPORT_STARTED)) {
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
                __shutdown_transport_flow();
                __post_channel_event(shared_from_this(), 0);
                return;
            }
        }
    }

    transport_error udp_transport::read_for_once() {
        while (__is_status(TRANSPORT_STARTED)) {
            transport_error err = __async_read(READ_ONCE);
            if (err != ERROR_AGAIN) {
                return err;
            }
        }
        return ERROR_UNSTART;
    }

    transport_error udp_transport::read_for_loop() {
        while (__is_status(TRANSPORT_STARTED)) {
            transport_error err = __async_read(READ_LOOP);
            if (err != ERROR_AGAIN) {
                return err;
            }
        }
        return ERROR_UNSTART;
    }

    transport_error udp_transport::send(const block_t *b,
                                        int32_t size,
                                        const address &address) {
        if (!b || size == 0) {
            PUMP_ERR_LOG("udp_transport: send failed with invalid buffer");
            return ERROR_INVALID;
        }

        if (PUMP_UNLIKELY(!__is_status(TRANSPORT_STARTED))) {
            PUMP_ERR_LOG("udp_transport: send failed for transport no statred");
            return ERROR_UNSTART;
        }

        if (PUMP_LIKELY(flow_->send(b, size, address) > 0)) {
            return ERROR_OK;
        }

        return ERROR_AGAIN;
    }

#if defined(PUMP_HAVE_IOCP)
    void udp_transport::on_read_event(net::iocp_task_ptr iocp_task) {
#else
    void udp_transport::on_read_event() {
#endif
        auto flow = flow_.get();

        address from_addr;
#if defined(PUMP_HAVE_IOCP)
        int32_t size = 0;
        const block_t *b = iocp_task->get_processed_data(&size);
#else
        block_t b[MAX_TRANSPORT_BUFFER_SIZE];
        int32_t size = flow->read_from(b, MAX_TRANSPORT_BUFFER_SIZE, &from_addr);
#endif
        if (PUMP_LIKELY(size > 0)) {
#if defined(PUMP_HAVE_IOCP)
            int32_t addrlen = 0;
            sockaddr *addr = iocp_task->get_remote_address(&addrlen);
            from_addr.set(addr, addrlen);
#endif
            // If read state is READ_ONCE, change it to READ_PENDING.
            // If read state is READ_LOOP, last state will be seted to READ_LOOP.
            uint32_t last_state = (uint32_t)READ_ONCE;
            read_state_.compare_exchange_strong(last_state, (uint32_t)READ_PENDING);

            // Do read callback.
            cbs_.read_from_cb(b, size, from_addr);

            // If last read state is READ_ONCE, try to change read state to READ_NONE.
            if (last_state == (uint32_t)READ_ONCE) {
                last_state = (uint32_t)READ_PENDING;
                if (read_state_.compare_exchange_strong(last_state, (uint32_t)READ_NONE)) {
                    return;
                }
            }
        }

        // If transport is not in started state, try to interrupt the transport.
        if (!__is_status(TRANSPORT_STARTED)) {
            __interrupt_and_trigger_callbacks();
            return;
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow->post_read(iocp_task) == flow::FLOW_ERR_ABORT) {
            PUMP_WARN_LOG("udp_transport: handle read event failed for flow post read task failed");
        }
#else
        PUMP_DEBUG_CHECK(r_tracker_->set_tracked(true));
#endif
    }

    bool udp_transport::__open_transport_flow() {
        // Init udp transport flow.
        PUMP_ASSERT(!flow_);
        flow_.reset(object_create<flow::flow_udp>(), object_delete<flow::flow_udp>);
        if (flow_->init(shared_from_this(), local_address_) != flow::FLOW_ERR_NO) {
            PUMP_ERR_LOG("udp_transport: open transport flow failed for flow init failed");
            return false;
        }

        // Set channel fd.
        poll::channel::__set_fd(flow_->get_fd());

        return true;
    }

    transport_error udp_transport::__async_read(uint32_t state) {
        uint32_t current_state = __change_read_state(state);
        if (current_state >= (uint32_t)READ_PENDING) {
            return ERROR_OK;
        } else if (current_state == (uint32_t)READ_INVALID) {
            return ERROR_AGAIN;
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow_->post_read() == flow::FLOW_ERR_ABORT) {
            PUMP_ERR_LOG("udp_transport: async read failed for flow post read task fialed");
            return ERROR_FAULT;
        }
#else
        if (!__start_read_tracker(shared_from_this())) {
            PUMP_ERR_LOG("udp_transport: async read failed for starting read tracker fialed");
            return ERROR_FAULT;
        }
#endif
        return ERROR_OK;
    }

}  // namespace transport
}  // namespace pump
