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
        if (!__set_status(TRANSPORT_INITED, TRANSPORT_STARTING))
            return ERROR_INVALID;

        PUMP_ASSERT(sv != nullptr);
        __set_service(sv);

        PUMP_DEBUG_ASSIGN(cbs.read_from_cb && cbs.stopped_cb, cbs_, cbs);

        toolkit::defer defer([&]() {
            __close_flow();
            __set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
        });

        if (!__open_flow())
            return ERROR_FAULT;

        defer.clear();

        PUMP_DEBUG_CHECK(__set_status(TRANSPORT_STARTING, TRANSPORT_STARTED));

        return ERROR_OK;
    }

    void udp_transport::stop() {
        while (__is_status(TRANSPORT_STARTED)) {
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
                __close_flow();
#if !defined(PUMP_HAVE_IOCP)
                __stop_read_tracker();
#endif
                return;
            }
        }
    }

    transport_error udp_transport::read_for_once() {
        while (true) {
            if (!is_started())
                return ERROR_UNSTART;

            uint32 old_state = read_state_.load();
            if (old_state == READ_ONCE || old_state == READ_LOOP) {
                if (!read_state_.compare_exchange_strong(old_state, READ_ONCE))
                    continue;
                break;
            }

            old_state = READ_NONE;
            if (read_state_.compare_exchange_strong(old_state, READ_ONCE)) {
#if defined(PUMP_HAVE_IOCP)
                if (!flow_->want_to_read() == flow::FLOW_ERR_ABORT)
#else
                if (!__start_read_tracker(shared_from_this()))
#endif
                    return ERROR_FAULT;
                break;
            }

            old_state = READ_PENDING;
            if (read_state_.compare_exchange_strong(old_state, READ_ONCE))
                break;
        }

        return ERROR_OK;
    }

    transport_error udp_transport::read_for_loop() {
        while (true) {
            if (!is_started())
                return ERROR_UNSTART;

            uint32 old_state = read_state_.load();
            if (old_state == READ_ONCE || old_state == READ_LOOP) {
                if (read_state_.compare_exchange_strong(old_state, READ_LOOP))
                    continue;
                break;
            }

            old_state = READ_NONE;
            if (read_state_.compare_exchange_strong(old_state, READ_LOOP)) {
#if defined(PUMP_HAVE_IOCP)
                if (flow_->want_to_read() == flow::FLOW_ERR_ABORT)
#else
                if (!__start_read_tracker(shared_from_this()))
#endif
                    return ERROR_FAULT;

                break;
            }

            old_state = READ_PENDING;
            if (read_state_.compare_exchange_strong(old_state, READ_LOOP))
                break;
        }

        return ERROR_OK;
    }

    transport_error udp_transport::send(c_block_ptr b,
                                        uint32 size,
                                        const address &remote_address) {
        PUMP_ASSERT(b && size > 0);

        if (PUMP_UNLIKELY(!is_started()))
            return ERROR_UNSTART;

        flow_->send(b, size, remote_address);

        return ERROR_OK;
    }

#if defined(PUMP_HAVE_IOCP)
    void udp_transport::on_read_event(void_ptr iocp_task) {
#else
    void udp_transport::on_read_event() {
#endif
        auto flow = flow_.get();
        if (!flow->is_valid())
            return;

        uint32 pending_state = READ_PENDING;
        uint32 old_state = read_state_.exchange(pending_state);

        address addr;
        int32 size = 0;
#if defined(PUMP_HAVE_IOCP)
        c_block_ptr b = flow->read_from(iocp_task, &size, &addr);
#else
        c_block_ptr b = flow->read_from(&size, &addr);
#endif
        if (size > 0 && cbs_.read_from_cb)
            cbs_.read_from_cb(b, size, addr);

        if (old_state == READ_ONCE) {
            if (read_state_.compare_exchange_strong(pending_state, READ_NONE))
                return;
        }

#if defined(PUMP_HAVE_IOCP)
        flow->want_to_read();
#else
        if (r_tracker_->is_started())
            r_tracker_->set_tracked(true);
#endif
    }

    bool udp_transport::__open_flow() {
        PUMP_ASSERT(!flow_);
        flow_.reset(object_create<flow::flow_udp>(), object_delete<flow::flow_udp>);
        if (flow_->init(shared_from_this(), local_address_) != flow::FLOW_ERR_NO)
            return false;

        // Set channel fd
        poll::channel::__set_fd(flow_->get_fd());

        return true;
    }

}  // namespace transport
}  // namespace pump
