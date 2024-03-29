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

#include "pump/transport/tls_acceptor.h"
#include "pump/transport/tls_transport.h"

namespace pump {
namespace transport {

tls_acceptor::tls_acceptor(
    tls_credentials xcred,
    const address &listen_address,
    uint64_t handshake_timeout_ns) noexcept
  : base_acceptor(transport_tls_acceptor, listen_address),
    xcred_(xcred),
    handshake_timeout_ns_(handshake_timeout_ns) {
}

tls_acceptor::~tls_acceptor() {
    __stop_all_handshakers();
    delete_tls_credentials(xcred_);
}

error_code tls_acceptor::start(service *sv, const acceptor_callbacks &cbs) {
    if (sv == nullptr) {
        pump_debug_log("service invalid");
        return error_invalid;
    }

    if (!cbs.accepted_cb ||
        !cbs.stopped_cb) {
        pump_debug_log("callbacks invalid");
        return error_invalid;
    }

    if (xcred_ == nullptr) {
        pump_debug_log("cert invalid");
        return error_invalid;
    }

    if (!__set_state(state_none, state_starting)) {
        pump_debug_log("tls acceptor already started");
        return error_fault;
    }

    do {
        cbs_ = cbs;

        __set_service(sv);

        if (!__open_accept_flow()) {
            pump_debug_log("open tls acceptor's flow failed");
            break;
        }

        if (!__install_accept_tracker(shared_from_this())) {
            pump_debug_log("install tls acceptor's tracker failed");
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

void tls_acceptor::stop() {
    // When stopping done, tracker event will trigger stopped callback.
    if (__set_state(state_started, state_stopping)) {
        __close_accept_flow();
        __stop_all_handshakers();
        __post_channel_event(shared_from_this(), channel_event_disconnected);
    }
}

void tls_acceptor::on_read_event() {
    // Wait starting end
    while (__is_state(state_starting, std::memory_order_relaxed)) {
        // pump_debug_log("tls acceptor starting, wait");
    }

    do {
        address local_address, remote_address;
        pump_socket fd = flow_->accept(&local_address, &remote_address);
        if (fd > 0) {
            tls_handshaker *handshaker = __create_handshaker();
            if (pump_unlikely(handshaker == nullptr)) {
                pump_warn_log("create tls handshaker failed");
                net::close(fd);
                break;
            }

            tls_handshaker::tls_handshaker_callbacks handshaker_cbs;
            handshaker_cbs.handshaked_cb = pump_bind(
                &tls_acceptor::on_handshaked,
                shared_from_this(),
                _1,
                _2);
            handshaker_cbs.stopped_cb = pump_bind(
                &tls_acceptor::on_handshake_stopped,
                shared_from_this(),
                _1);
            if (!handshaker->init(
                    fd,
                    false,
                    xcred_,
                    local_address,
                    remote_address)) {
                pump_debug_log("init tls handshaker failed");
                __remove_handshaker(handshaker);
                break;
            }
            if (!handshaker->start(
                    get_service(),
                    handshake_timeout_ns_,
                    handshaker_cbs)) {
                pump_debug_log("start tls handshaker failed");
                __remove_handshaker(handshaker);
                break;
            }
        }
    } while (false);

    if (!__start_accept_tracker()) {
        if (__is_state(state_started)) {
            pump_err_log("start tls acceptor's tracker failed");
        }
    }
}

void tls_acceptor::on_handshaked(
    tls_acceptor_wptr acceptor,
    tls_handshaker *handshaker,
    bool success) {
    auto acceptor_locker = acceptor.lock();
    if (!acceptor_locker ||
        !acceptor_locker->__remove_handshaker(handshaker)) {
        return;
    }

    if (success && acceptor_locker->is_started()) {
        tls_transport_sptr tls_transport = tls_transport::create();
        if (!tls_transport) {
            pump_warn_log("new tls transport object failed");
            return;
        }
        tls_transport->init(
            handshaker->unlock_flow(),
            handshaker->get_local_address(),
            handshaker->get_remote_address());

        base_transport_sptr transport = tls_transport;
        acceptor_locker->cbs_.accepted_cb(transport);
    }
}

void tls_acceptor::on_handshake_stopped(
    tls_acceptor_wptr acceptor,
    tls_handshaker *handshaker) {
    auto acceptor_locker = acceptor.lock();
    if (acceptor_locker) {
        acceptor_locker->__remove_handshaker(handshaker);
    }
}

bool tls_acceptor::__open_accept_flow() {
    // Init tls acceptor flow.
    flow_.reset(
        pump_object_create<flow::flow_tls_acceptor>(),
        pump_object_destroy<flow::flow_tls_acceptor>);
    if (!flow_) {
        pump_warn_log("new tls acceptor's flow failed");
        return false;
    } else if (!flow_->init(shared_from_this(), listen_address_)) {
        pump_debug_log("init tls acceptor's flow failed");
        return false;
    }

    // Set channel fd
    channel::__set_fd(flow_->get_fd());

    return true;
}
void tls_acceptor::__close_accept_flow() {
    if (flow_) {
        flow_->close();
    }
}

tls_handshaker *tls_acceptor::__create_handshaker() {
    tls_handshaker_sptr handshaker(
        pump_object_create<tls_handshaker>(),
        pump_object_destroy<tls_handshaker>);
    if (!handshaker) {
        pump_warn_log("new tls handshaker object failed");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(handshaker_mx_);
    handshakers_[handshaker.get()] = handshaker;
    return handshaker.get();
}

bool tls_acceptor::__remove_handshaker(tls_handshaker *handshaker) {
    std::lock_guard<std::mutex> lock(handshaker_mx_);
    auto it = handshakers_.find(handshaker);
    if (it == handshakers_.end()) {
        return false;
    }
    handshakers_.erase(it);
    return true;
}

void tls_acceptor::__stop_all_handshakers() {
    std::lock_guard<std::mutex> lock(handshaker_mx_);
    for (auto hs : handshakers_) {
        hs.second->stop();
    }
    handshakers_.clear();
}

}  // namespace transport
}  // namespace pump
