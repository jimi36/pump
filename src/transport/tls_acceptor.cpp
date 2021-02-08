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

    tls_acceptor::tls_acceptor(void_ptr xcred,
                               bool xcred_owner,
                               const address& listen_address,
                               int64_t handshake_timeout) 
      : base_acceptor(TLS_ACCEPTOR, listen_address), 
        xcred_(xcred), 
        xcred_owner_(xcred_owner) ,
        handshake_timeout_(handshake_timeout) {
    }

    tls_acceptor::~tls_acceptor() {
        if (xcred_owner_) {
            ssl::destory_tls_certificate(xcred_);
        }
    }

    int32_t tls_acceptor::start(service_ptr sv, const acceptor_callbacks &cbs) {
        if (!xcred_) {
            PUMP_ERR_LOG("tls_acceptor: start failed with invalid certificate");
            return ERROR_INVALID;
        }

        if (!sv) {
            PUMP_ERR_LOG("tls_acceptor: start failed with invalid service");
            return ERROR_INVALID;
        }

        if (!cbs.accepted_cb || !cbs.stopped_cb) {
            PUMP_ERR_LOG("tls_acceptor: start failed with invalid callbacks");
            return ERROR_INVALID;
        }

        if (!__set_state(TRANSPORT_INITED, TRANSPORT_STARTING)) {
            PUMP_ERR_LOG("tls_acceptor: start failed with wrong status");
            return ERROR_INVALID;
        }

        // Callbacks
        cbs_ = cbs;

        // Service
        __set_service(sv);

        toolkit::defer cleanup([&]() {
            __stop_accept_tracker();
            __close_accept_flow();
            __set_state(TRANSPORT_STARTING, TRANSPORT_ERROR);
        });

        if (!__open_accept_flow()) {
            PUMP_ERR_LOG("tls_acceptor: start failed for opening flow failed");
            return ERROR_FAULT;
        }

        if (!__start_accept_tracker(shared_from_this())) {
            PUMP_ERR_LOG("tls_acceptor: start failed for starting tracker failed");
            return ERROR_FAULT;
        }

        __set_state(TRANSPORT_STARTING, TRANSPORT_STARTED);

        cleanup.clear();

        return ERROR_OK;
    }

    void tls_acceptor::stop() {
        // When stopping done, tracker event will trigger stopped callback.
        if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
            __close_accept_flow();
            __post_channel_event(shared_from_this(), 0);
        }
    }

    void tls_acceptor::on_read_event() {
        address local_address, remote_address;
        pump_socket fd = flow_->accept(&local_address, &remote_address);
        if (PUMP_LIKELY(fd > 0)) {
            tls_handshaker_ptr handshaker = __create_handshaker();
            if (PUMP_LIKELY(!!handshaker)) {
                tls_handshaker::tls_handshaker_callbacks handshaker_cbs;
                handshaker_cbs.handshaked_cb =
                    pump_bind(&tls_acceptor::on_handshaked, shared_from_this(), _1, _2);
                handshaker_cbs.stopped_cb = 
                    pump_bind(&tls_acceptor::on_handshake_stopped, shared_from_this(), _1);

                // If handshaker is started error, handshaked callback will be
                // triggered. So we do nothing at here when started error. But if
                // acceptor stopped befere here, we shuold stop handshaking.
                handshaker->init(fd, false, xcred_, local_address, remote_address);
                if (handshaker->start(get_service(), handshake_timeout_, handshaker_cbs)) {
                    if (!__is_state(TRANSPORT_STARTING) &&
                        !__is_state(TRANSPORT_STARTED)) {
                        PUMP_DEBUG_LOG("tls_acceptor: handle read event failed for acceptor had stopped");
                        handshaker->stop();
                    }
                } else {
                    PUMP_DEBUG_LOG("tls_acceptor: handle read event failed for handshaker start failed");
                    __remove_handshaker(handshaker);
                }
            } else {
                PUMP_DEBUG_LOG("tls_acceptor: handle read event failed for creating handshaker failed");
                net::close(fd);
            }
        }

        if (__is_state(TRANSPORT_STARTING) || __is_state(TRANSPORT_STARTED)) {
            PUMP_DEBUG_CHECK(__resume_accept_tracker());
            return;
        }

        __stop_all_handshakers();

        __stop_accept_tracker();

        __trigger_interrupt_callbacks();
    }

    void tls_acceptor::on_handshaked(tls_acceptor_wptr wptr,
                                     tls_handshaker_ptr handshaker,
                                     bool succ) {
        PUMP_LOCK_WPOINTER(acceptor, wptr);
        if (!acceptor) {
            PUMP_DEBUG_LOG("tls_acceptor: handle handshaked event failed for invalid acceptor");
            handshaker->stop();
            return;
        }

        acceptor->__remove_handshaker(handshaker);

        if (succ && acceptor->__is_state(TRANSPORT_STARTED)) {
            auto flow = handshaker->unlock_flow();
            address local_address = handshaker->get_local_address();
            address remote_address = handshaker->get_remote_address();

            tls_transport_sptr tls_transport = tls_transport::create();
            tls_transport->init(flow, local_address, remote_address);

            base_transport_sptr transport = tls_transport;
            acceptor->cbs_.accepted_cb(transport);
        }
    }

    void tls_acceptor::on_handshake_stopped(tls_acceptor_wptr wptr,
                                            tls_handshaker_ptr handshaker) {
        PUMP_LOCK_WPOINTER(acceptor, wptr);
        if (!acceptor) {
            PUMP_DEBUG_LOG("tls_acceptor: handle handshaked stopped event failed for invalid acceptor");
            return;
        }

        acceptor->__remove_handshaker(handshaker);
    }

    bool tls_acceptor::__open_accept_flow() {
        // Init tls acceptor flow.
        PUMP_ASSERT(!flow_);
        flow_.reset(object_create<flow::flow_tls_acceptor>(),
                    object_delete<flow::flow_tls_acceptor>);

        if (flow_->init(shared_from_this(), listen_address_) != flow::FLOW_ERR_NO) {
            PUMP_WARN_LOG("tls_acceptor: open flow failed for flow init failed");
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

    tls_handshaker_ptr tls_acceptor::__create_handshaker() {
        tls_handshaker_sptr handshaker(object_create<tls_handshaker>(),
                                       object_delete<tls_handshaker>);
        std::lock_guard<std::mutex> lock(handshaker_mx_);
        handshakers_[handshaker.get()] = handshaker;
        return handshaker.get();
    }

    void tls_acceptor::__remove_handshaker(tls_handshaker_ptr handshaker) {
        std::lock_guard<std::mutex> lock(handshaker_mx_);
        handshakers_.erase(handshaker);
    }

    void tls_acceptor::__stop_all_handshakers() {
        std::lock_guard<std::mutex> lock(handshaker_mx_);
        for (auto hs : handshakers_) {
            hs.second->stop();
        }
    }

}  // namespace transport
}  // namespace pump
