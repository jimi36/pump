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
        if (!__set_status(TRANSPORT_INITED, TRANSPORT_STARTING))
            return ERROR_INVALID;

        PUMP_ASSERT(sv != nullptr);
        __set_service(sv);

        PUMP_DEBUG_ASSIGN(cbs.accepted_cb && cbs.stopped_cb, cbs_, cbs);

        toolkit::defer defer([&]() {
            __close_flow();
#if !defined(PUMP_HAVE_IOCP)
            __stop_tracker();
#endif
            __set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
        });

        if (!__open_flow())
            return ERROR_FAULT;

#if defined(PUMP_HAVE_IOCP)
        if (flow_->want_to_accept() != flow::FLOW_ERR_NO)
            return ERROR_FAULT;
#else
        if (!__start_tracker(shared_from_this()))
            return ERROR_FAULT;
#endif

        defer.clear();

        PUMP_DEBUG_CHECK(__set_status(TRANSPORT_STARTING, TRANSPORT_STARTED));

        return ERROR_OK;
    }

    void tcp_acceptor::stop() {
        // When stopping done, tracker event will trigger stopped callabck.
        if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
            __close_flow();
#if !defined(PUMP_HAVE_IOCP)
            __stop_tracker();
#endif
            __post_channel_event(shared_from_this(), 0);
        }
    }

#if defined(PUMP_HAVE_IOCP)
    void tcp_acceptor::on_read_event(void_ptr iocp_task) {
#else
    void tcp_acceptor::on_read_event() {
#endif
        auto flow = flow_.get();
        if (!flow->is_valid())
            return;

        address local_address, remote_address;
#if defined(PUMP_HAVE_IOCP)
        int32 fd = flow->accept(iocp_task, &local_address, &remote_address);
#else
        int32 fd = flow->accept(&local_address, &remote_address);
#endif
        if (fd > 0) {
            tcp_transport_sptr tcp_transport = tcp_transport::create_instance();
            tcp_transport->init(fd, local_address, remote_address);

            base_transport_sptr transport = tcp_transport;
            if (cbs_.accepted_cb)
                cbs_.accepted_cb(transport);
        }

        if (!is_started())
            return;

#if defined(PUMP_HAVE_IOCP)
        if (flow->want_to_accept() != flow::FLOW_ERR_NO)
            PUMP_ASSERT(false);
#else
        if (!tracker_->set_tracked(true))
            PUMP_ASSERT(false);
#endif
    }

    bool tcp_acceptor::__open_flow() {
        // Setup flow
        PUMP_ASSERT(!flow_);
        flow_.reset(object_create<flow::flow_tcp_acceptor>(),
                    object_delete<flow::flow_tcp_acceptor>);

        if (flow_->init(shared_from_this(), listen_address_) != flow::FLOW_ERR_NO)
            return false;

        // Set channel fd
        poll::channel::__set_fd(flow_->get_fd());

        return true;
    }

}  // namespace transport
}  // namespace pump
