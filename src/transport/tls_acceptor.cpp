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
        const address& listen_address,
        int64_t handshake_timeout) 
      : base_acceptor(TLS_ACCEPTOR, listen_address), 
        xcred_(xcred), 
        handshake_timeout_(handshake_timeout) {
    }

    tls_acceptor::~tls_acceptor() {
        __stop_all_handshakers();

        destory_tls_credentials(xcred_);
    }

    error_code tls_acceptor::start(
        service *sv, 
        const acceptor_callbacks &cbs) {
        PUMP_DEBUG_FAILED(
            !__set_state(TRANSPORT_INITED, TRANSPORT_STARTING), 
            "tls_acceptor: start failed for transport state incorrect",
            return ERROR_INVALID);

        bool ret = false;
        toolkit::defer cleanup([&]() {
            if (ret) {
                __set_state(TRANSPORT_STARTING, TRANSPORT_STARTED);
            } else {
                __set_state(TRANSPORT_STARTING, TRANSPORT_ERROR);
                __close_accept_flow();
            }
        });

        PUMP_DEBUG_FAILED(
            xcred_ == nullptr, 
            "tls_acceptor: start failed for cert invalid",
            return ERROR_INVALID);

        PUMP_DEBUG_FAILED(
            sv == nullptr, 
            "tls_acceptor: start failed for service invalid",
            return ERROR_INVALID);
        __set_service(sv);

        PUMP_DEBUG_FAILED(
            !cbs.accepted_cb || !cbs.stopped_cb,
            "tls_acceptor: start failed for callbacks invalid", 
            return ERROR_INVALID);
        cbs_ = cbs;

        if (!__open_accept_flow()) {
            PUMP_DEBUG_LOG("tls_acceptor: start failed for opening flow failed");
            return ERROR_FAULT;
        }

        if (!__start_accept_tracker(shared_from_this())) {
            PUMP_WARN_LOG("tls_acceptor: start failed for starting tracker failed");
            return ERROR_FAULT;
        }

        ret = true;

        return ERROR_OK;
    }

    void tls_acceptor::stop() {
        // When stopping done, tracker event will trigger stopped callback.
        if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
            __close_accept_flow();
            __stop_all_handshakers();
            __post_channel_event(shared_from_this(), 0);
        }
    }

    void tls_acceptor::on_read_event() {
        address local_address, remote_address;
        pump_socket fd = flow_->accept(&local_address, &remote_address);
        if (PUMP_LIKELY(fd > 0)) {
            tls_handshaker *handshaker = __create_handshaker();
            if (PUMP_LIKELY(handshaker != nullptr)) {
                tls_handshaker::tls_handshaker_callbacks handshaker_cbs;
                handshaker_cbs.handshaked_cb =
                    pump_bind(&tls_acceptor::on_handshaked, shared_from_this(), _1, _2);
                handshaker_cbs.stopped_cb = 
                    pump_bind(&tls_acceptor::on_handshake_stopped, shared_from_this(), _1);
                handshaker->init(fd, false, xcred_, local_address, remote_address);
                if (!handshaker->start(get_service(), handshake_timeout_, handshaker_cbs)) {
                    PUMP_DEBUG_LOG(
                        "tls_acceptor: handle read failed for starting handshaker failed");
                    __remove_handshaker(handshaker);
                }
            } else {
                PUMP_WARN_LOG(
                    "tls_acceptor: handle read failed for creating handshaker failed");
                net::close(fd);
            }
        }

        if(!__resume_accept_tracker()) {
            PUMP_WARN_LOG(
                "tls_acceptor: handle read failed for resuming tracker failed");
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
                PUMP_WARN_LOG("tls_acceptor: handle handshaked failed for creating tls transport");
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
            PUMP_WARN_LOG("tls_acceptor: open flow failed for creating flow failed");
            return false;
        }
        if (flow_->init(shared_from_this(), listen_address_) != ERROR_OK) {
            PUMP_DEBUG_LOG("tls_acceptor: open flow failed for initing flow failed");
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

    tls_handshaker* tls_acceptor::__create_handshaker() {
        tls_handshaker_sptr handshaker(
            object_create<tls_handshaker>(),
            object_delete<tls_handshaker>);
        if (!handshaker) {
            PUMP_WARN_LOG("tls_acceptor: create handshaker failed");
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
