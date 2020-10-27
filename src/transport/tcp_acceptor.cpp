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

#include "pump/transport/tcp_acceptor.h"
#include "pump/transport/tcp_transport.h"

namespace pump {
namespace transport {

    tcp_acceptor::tcp_acceptor(const address &listen_address) noexcept
        : base_acceptor(TCP_ACCEPTOR, listen_address) {
    }

    transport_error tcp_acceptor::start(service_ptr sv, const acceptor_callbacks &cbs) {
        if (!sv) {
            PUMP_ERR_LOG("tcp_acceptor::start: service invalid");
            return ERROR_INVALID;
        }

        if (!cbs.accepted_cb || !cbs.stopped_cb) {
            PUMP_ERR_LOG("tcp_acceptor::start: callbacks invalid");
            return ERROR_INVALID;
        }

        if (!__set_status(TRANSPORT_INITED, TRANSPORT_STARTING)) {
            PUMP_ERR_LOG("tcp_acceptor::start: acceptor has started");
            return ERROR_INVALID;
        }

        // Callbacks
        cbs_ = cbs;

        // Service
        __set_service(sv);

        toolkit::defer cleanup([&]() {
            __close_accept_flow();
#if !defined(PUMP_HAVE_IOCP)
            __stop_accept_tracker();
#endif
            __set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
        });

        if (!__open_accept_flow()) {
            PUMP_ERR_LOG("tcp_acceptor::start: open accept flow failed");
            return ERROR_FAULT;
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow_->post_accept() != flow::FLOW_ERR_NO) {
            PUMP_ERR_LOG("tcp_acceptor::start: want to accept failed");
            return ERROR_FAULT;
        }
#else
        if (!__start_accept_tracker(shared_from_this())) {
            PUMP_ERR_LOG("tcp_acceptor::start: start tracker failed");
            return ERROR_FAULT;
        }
#endif
        __set_status(TRANSPORT_STARTING, TRANSPORT_STARTED);

        cleanup.clear();

        return ERROR_OK;
    }

    void tcp_acceptor::stop() {
        // When stopping done, tracker event will trigger stopped callabck.
        if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
            __close_accept_flow();
            __post_channel_event(shared_from_this(), 0);
        } else {
            PUMP_DEBUG_LOG("tcp_acceptor::stop: acceptor not started");
        }
    }

#if defined(PUMP_HAVE_IOCP)
    void tcp_acceptor::on_read_event(net::iocp_task_ptr iocp_task) {
#else
    void tcp_acceptor::on_read_event() {
#endif
        auto flow = flow_.get();

        address local_address, remote_address;
#if defined(PUMP_HAVE_IOCP)
        int32 fd = flow->accept(iocp_task, &local_address, &remote_address);
#else
        int32 fd = flow->accept(&local_address, &remote_address);
#endif
        if (fd > 0) {
            tcp_transport_sptr tcp_transport = tcp_transport::create();
            tcp_transport->init(fd, local_address, remote_address);

            base_transport_sptr transport = tcp_transport;
            cbs_.accepted_cb(transport);
        }

        if (__is_status(TRANSPORT_STARTING) || __is_status(TRANSPORT_STARTED)) {
#if defined(PUMP_HAVE_IOCP)
            if (flow->post_accept() != flow::FLOW_ERR_NO) {
                PUMP_ERR_LOG("tcp_acceptor::on_read_event: want to accept failed");
            }
#else
            PUMP_DEBUG_CHECK(tracker_->set_tracked(true));
#endif
            return;
        }

#if !defined(PUMP_HAVE_IOCP)
        __stop_accept_tracker();
#endif
        __trigger_interrupt_callbacks();
    }

    bool tcp_acceptor::__open_accept_flow() {
        // Init tcp acceptor flow.
        PUMP_ASSERT(!flow_);
        flow_.reset(object_create<flow::flow_tcp_acceptor>(),
                    object_delete<flow::flow_tcp_acceptor>);
        if (flow_->init(shared_from_this(), listen_address_) != flow::FLOW_ERR_NO) {
            PUMP_ERR_LOG("tcp_acceptor::__open_flow: flow init failed");
            return false;
        }

        // Set channel fd
        poll::channel::__set_fd(flow_->get_fd());

        return true;
    }

    void tcp_acceptor::__close_accept_flow() {
        if (flow_) {
            flow_->close();
        }
    }

}  // namespace transport
}  // namespace pump
