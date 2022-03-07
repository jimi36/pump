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
    int64_t handshake_timeout) noexcept :
    base_acceptor(transport_tls_acceptor, listen_address),
    xcred_(xcred),
    handshake_timeout_(handshake_timeout) {}

tls_acceptor::~tls_acceptor() {
    __stop_all_handshakers();

    delete_tls_credentials(xcred_);
}

error_code tls_acceptor::start(service *sv, const acceptor_callbacks &cbs) {
    if (sv == nullptr) {
        pump_warn_log("service is invalid");
        return error_invalid;
    }

    if (!cbs.accepted_cb || !cbs.stopped_cb) {
        pump_warn_log("callbacks is invalid");
        return error_invalid;
    }

    if (xcred_ == nullptr) {
        pump_warn_log("tls acceptor's cert is invalid");
        return error_invalid;
    }

    if (!__set_state(state_none, state_starting)) {
        pump_warn_log("tls acceptor is already started before");
        return error_fault;
    }

    do {
        cbs_ = cbs;

        __set_service(sv);

        if (!__open_accept_flow()) {
            pump_warn_log("open tls acceptor's flow failed");
            break;
        }

        if (!__start_accept_tracker(shared_from_this())) {
            pump_warn_log("start tls acceptor's tracker failed");
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
    address local_address, remote_address;
    pump_socket fd = flow_->accept(&local_address, &remote_address);
    if (pump_likely(fd > 0)) {
        tls_handshaker *handshaker = __create_handshaker();
        if (pump_likely(handshaker != nullptr)) {
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
                pump_warn_log("init tls handshaker failed");
                __remove_handshaker(handshaker);
            }
            if (!handshaker->start(
                    get_service(),
                    handshake_timeout_,
                    handshaker_cbs)) {
                pump_warn_log("start tls handshaker failed");
                __remove_handshaker(handshaker);
            }
        } else {
            pump_warn_log("create tls handshaker failed");
            net::close(fd);
        }
    }

    if (!__resume_accept_tracker()) {
        pump_warn_log("resume tls acceptor's tracker failed");
    }
}

void tls_acceptor::on_handshaked(
    tls_acceptor_wptr wptr,
    tls_handshaker *handshaker,
    bool succ) {
    auto acceptor = wptr.lock();
    if (!acceptor || !acceptor->__remove_handshaker(handshaker)) {
        return;
    }

    if (succ && acceptor->is_started()) {
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
        acceptor->cbs_.accepted_cb(transport);
    }
}

void tls_acceptor::on_handshake_stopped(
    tls_acceptor_wptr wptr,
    tls_handshaker *handshaker) {
    auto acceptor = wptr.lock();
    if (acceptor) {
        acceptor->__remove_handshaker(handshaker);
    }
}

bool tls_acceptor::__open_accept_flow() {
    // Init tls acceptor flow.
    flow_.reset(
        object_create<flow::flow_tls_acceptor>(),
        object_delete<flow::flow_tls_acceptor>);
    if (!flow_) {
        pump_warn_log("new tls acceptor's flow failed");
        return false;
    }
    if (flow_->init(shared_from_this(), listen_address_) != error_none) {
        pump_warn_log("init tls acceptor's flow failed");
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
        object_create<tls_handshaker>(),
        object_delete<tls_handshaker>);
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
