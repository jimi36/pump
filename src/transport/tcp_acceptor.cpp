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
  : base_acceptor(transport_tcp_acceptor, listen_address) {}

error_code tcp_acceptor::start(service *sv, const acceptor_callbacks &cbs) {
    if (sv == nullptr) {
        pump_debug_log("service is invalid");
        return error_invalid;
    }

    if (!cbs.accepted_cb ||
        !cbs.stopped_cb) {
        pump_debug_log("callbacks is invalid");
        return error_invalid;
    }

    if (!__set_state(state_none, state_starting)) {
        pump_debug_log("tcp acceptor already started");
        return error_fault;
    }

    do {
        cbs_ = cbs;

        __set_service(sv);

        if (!__open_accept_flow()) {
            pump_debug_log("open tcp acceptor's flow failed");
            break;
        }

        if (!__install_accept_tracker(shared_from_this())) {
            pump_debug_log("install tcp acceptor's tracker failed");
            break;
        }

        if (__set_state(state_starting, state_started)) {
            return error_none;
        }
    } while (false);

    __set_state(state_starting, state_error);
    __close_accept_flow();

    return error_fault;
}

void tcp_acceptor::stop() {
    // When stopping done, tracker event will trigger stopped callabck.
    if (__set_state(state_started, state_stopping)) {
        __close_accept_flow();
        __post_channel_event(shared_from_this(), channel_event_disconnected);
    }
}

void tcp_acceptor::on_read_event() {
    // Wait starting end
    while (__is_state(state_starting, std::memory_order_relaxed)) {
        //pump_debug_log("tcp acceptor starting, wait");
    }

    address local_address;
    address remote_address;
    pump_socket fd = flow_->accept(&local_address, &remote_address);
    if (fd > 0) {
        tcp_transport_sptr tcp_transport = tcp_transport::create();
        if (tcp_transport) {
            tcp_transport->init(fd, local_address, remote_address);
            base_transport_sptr transport = tcp_transport;
            cbs_.accepted_cb(transport);
        } else {
            pump_warn_log("new tcp transport object failed");
            net::close(fd);
        }
    }

    if (!__start_accept_tracker()) {
        if (__is_state(state_started)) {
            pump_err_log("start tcp acceptor's tracker failed");
        }
    }
}

bool tcp_acceptor::__open_accept_flow() {
    // Init tcp acceptor flow.
    flow_.reset(
        object_create<flow::flow_tcp_acceptor>(),
        object_delete<flow::flow_tcp_acceptor>);
    if (!flow_) {
        pump_warn_log("new tcp acceptor's flow object failed");
        return false;
    } else if (!flow_->init(shared_from_this(), listen_address_)) {
        pump_debug_log("init tcp acceptor's flow failed");
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
