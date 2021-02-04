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

    int32_t tcp_acceptor::start(service_ptr sv, const acceptor_callbacks &cbs) {
        if (!sv) {
            PUMP_ERR_LOG("tcp_acceptor: start failed with invalid service");
            return ERROR_INVALID;
        }

        if (!cbs.accepted_cb || !cbs.stopped_cb) {
            PUMP_ERR_LOG("tcp_acceptor: start failed with invalid callbacks");
            return ERROR_INVALID;
        }

        if (!__set_state(TRANSPORT_INITED, TRANSPORT_STARTING)) {
            PUMP_ERR_LOG("tcp_acceptor: start failed with wrong status");
            return ERROR_INVALID;
        }

        // Callbacks
        cbs_ = cbs;

        // Service
        __set_service(sv);

        toolkit::defer cleanup([&]() {
            __close_accept_flow();
            __stop_accept_tracker();
            __set_state(TRANSPORT_STARTING, TRANSPORT_ERROR);
        });

        if (!__open_accept_flow()) {
            PUMP_ERR_LOG("tcp_acceptor: start failed for opening flow failed");
            return ERROR_FAULT;
        }

        if (!__start_accept_tracker(shared_from_this())) {
            PUMP_ERR_LOG("tcp_acceptor: start failed for starting tracker failed");
            return ERROR_FAULT;
        }

        __set_state(TRANSPORT_STARTING, TRANSPORT_STARTED);

        cleanup.clear();

        return ERROR_OK;
    }

    void tcp_acceptor::stop() {
        // When stopping done, tracker event will trigger stopped callabck.
        if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
            __close_accept_flow();
            __post_channel_event(shared_from_this(), 0);
        }
    }

    void tcp_acceptor::on_read_event() {
        address local_address, remote_address;
        pump_socket fd = flow_->accept(&local_address, &remote_address);
        if (fd > 0) {
            tcp_transport_sptr tcp_transport = tcp_transport::create();
            tcp_transport->init(fd, local_address, remote_address);

            base_transport_sptr transport = tcp_transport;
            cbs_.accepted_cb(transport);
        }

        if (__is_state(TRANSPORT_STARTING) || __is_state(TRANSPORT_STARTED)) {
            PUMP_DEBUG_CHECK(__resume_accept_tracker());
            return;
        }

        __stop_accept_tracker();
        __trigger_interrupt_callbacks();
    }

    bool tcp_acceptor::__open_accept_flow() {
        // Init tcp acceptor flow.
        PUMP_ASSERT(!flow_);
        flow_.reset(object_create<flow::flow_tcp_acceptor>(),
                    object_delete<flow::flow_tcp_acceptor>);
        if (flow_->init(shared_from_this(), listen_address_) != flow::FLOW_ERR_NO) {
            PUMP_WARN_LOG("tcp_acceptor: open flow failed for flow init failed");
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
