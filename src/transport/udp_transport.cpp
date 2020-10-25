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

    udp_transport::udp_transport(const address &local_address) noexcept
        : base_transport(UDP_TRANSPORT, nullptr, -1) {
        local_address_ = local_address;
    }

    transport_error udp_transport::start(service_ptr sv,
                                         int32 max_pending_send_size,
                                         const transport_callbacks &cbs) {
        if (!sv) {
            PUMP_ERR_LOG("udp_transport::start: service invalid");
            return ERROR_INVALID;
        }

        if (!cbs.read_from_cb || !cbs.stopped_cb) {
            PUMP_ERR_LOG("udp_transport::start: callbacks invalid");
            return ERROR_INVALID;
        }

        if (!__set_status(TRANSPORT_INITED, TRANSPORT_STARTING)) {
            PUMP_ERR_LOG("udp_transport::start: has started");
            return ERROR_INVALID;
        }

        // Callbacks
        cbs_ = cbs;

        // Service
        __set_service(sv);

        toolkit::defer cleanup([&]() {
            __close_transport_flow();
            __set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
        });

        if (!__open_transport_flow()) {
            PUMP_ERR_LOG("udp_transport::start: open flow failed");
            return ERROR_FAULT;
        }

        __set_status(TRANSPORT_STARTING, TRANSPORT_STARTED);

        cleanup.clear();

        return ERROR_OK;
    }

    void udp_transport::stop() {
        while (__is_status(TRANSPORT_STARTED)) {
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
                while (true) {
                    transport_error err = __async_read(READ_ONCE);
                    if (err == ERROR_FAULT) {
                        __post_channel_event(shared_from_this(), 0);
                        return;
                    } else if (err == ERROR_OK) {
                        __shutdown_transport_flow();
                        return;
                    }
                }
            }
        }
    }

    transport_error udp_transport::read_for_once() {
        while (__is_status(TRANSPORT_STARTED, std::memory_order_relaxed)) {
            transport_error err = __async_read(READ_ONCE);
            if (err != ERROR_AGAIN) {
                return err;
            }
        }
        return ERROR_UNSTART;
    }

    transport_error udp_transport::read_for_loop() {
        while (__is_status(TRANSPORT_STARTED, std::memory_order_relaxed)) {
            transport_error err = __async_read(READ_LOOP);
            if (err != ERROR_AGAIN) {
                return err;
            }
        }
        return ERROR_UNSTART;
    }

    transport_error udp_transport::send(c_block_ptr b,
                                        uint32 size,
                                        const address &address) {
        if (!b || size == 0) {
            PUMP_ERR_LOG("udp_transport::send: buffer invalid");
            return ERROR_INVALID;
        }

        if (PUMP_UNLIKELY(!__is_status(TRANSPORT_STARTED, std::memory_order_relaxed))) {
            PUMP_ERR_LOG("udp_transport::send: not statred");
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

        // Get and change read state to READ_PENDING.
        uint32 pending_state = READ_PENDING;
        uint32 old_state = read_state_.exchange(pending_state);

        address addr;
        int32 size = 0;
#if defined(PUMP_HAVE_IOCP)
        c_block_ptr b = flow->read_from(iocp_task, &size, &addr);
#else
        c_block_ptr b = flow->read_from(&size, &addr);
#endif
        if (PUMP_LIKELY(size > 0)) {
            cbs_.read_from_cb(b, size, addr);
        }

        // If transport is not in started state, then interrupt this transport.
        if (!__is_status(TRANSPORT_STARTED)) {
            __interrupt_and_trigger_callbacks();
            return;
        }

        // If transport old read state is READ_ONCE, then change it from READ_PENDING
        // to READ_NONE.
        if (old_state == READ_ONCE &&
            read_state_.compare_exchange_strong(pending_state, READ_NONE)) {
            return;
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow->want_to_read() == flow::FLOW_ERR_ABORT) {
            PUMP_WARN_LOG("udp_transport::on_read_event: flow want_to_read failed");
        }
#else
        //if (!r_tracker_->is_started()) {
        //    PUMP_WARN_LOG("udp_transport::on_read_event: read tracker not started");
        //    return;
        //}
        PUMP_DEBUG_CHECK(r_tracker_->set_tracked(true));
#endif
    }

    bool udp_transport::__open_transport_flow() {
        // Init udp transport flow.
        PUMP_ASSERT(!flow_);
        flow_.reset(object_create<flow::flow_udp>(), object_delete<flow::flow_udp>);
        if (flow_->init(shared_from_this(), local_address_) != flow::FLOW_ERR_NO) {
            PUMP_ERR_LOG("udp_transport::__open_flow: flow init failed");
            return false;
        }

        // Set channel fd.
        poll::channel::__set_fd(flow_->get_fd());

        return true;
    }

    transport_error udp_transport::__async_read(uint32 state) {
        uint32 old_state = __change_read_state(state);
        if (old_state == READ_INVALID) {
            return ERROR_AGAIN;
        } else if (old_state >= READ_ONCE) {
            return ERROR_OK;
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow_->want_to_read() == flow::FLOW_ERR_ABORT) {
            PUMP_ERR_LOG("udp_transport::__async_read: flow want_to_read fialed");
            return ERROR_FAULT;
        }
#else
        if (!__start_read_tracker(shared_from_this())) {
            PUMP_ERR_LOG("udp_transport::__async_read: start read tracker fialed");
            return ERROR_FAULT;
        }
#endif
        return ERROR_OK;
    }

}  // namespace transport
}  // namespace pump
