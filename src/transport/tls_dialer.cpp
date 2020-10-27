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

#include "pump/ssl/ssl_helper.h"
#include "pump/transport/tls_dialer.h"
#include "pump/transport/tls_transport.h"

namespace pump {
namespace transport {

    tls_dialer::tls_dialer(const address &local_address,
                           const address &remote_address,
                           int64 dial_timeout,
                           int64 handshake_timeout) noexcept
        : base_dialer(TLS_DIALER, local_address, remote_address, dial_timeout),
          xcred_(nullptr),
          handshake_timeout_(handshake_timeout) {
        xcred_ = ssl::create_tls_client_certificate();
    }

    transport_error tls_dialer::start(service_ptr sv, const dialer_callbacks &cbs) {
        if (!xcred_) {
            PUMP_ERR_LOG("transport::tls_dialer::start: certificate invalid");
            return ERROR_INVALID;
        }

        if (!sv) {
            PUMP_ERR_LOG("transport::tls_dialer::start: service invalid");
            return ERROR_INVALID;
        }

        if (!cbs.dialed_cb || !cbs.stopped_cb || !cbs.timeout_cb) {
            PUMP_ERR_LOG("transport::tls_dialer::start: callbacks invalid");
            return ERROR_INVALID;
        }

        if (!__set_status(TRANSPORT_INITED, TRANSPORT_STARTING)) {
            PUMP_ERR_LOG("transport::tls_dialer::start: dialer had be started before");
            return ERROR_INVALID;
        }

        // Callbacks
        cbs_ = cbs;

        // Service
        __set_service(sv);

        toolkit::defer cleanup([&]() {
            __stop_dial_timer();
#if !defined(PUMP_HAVE_IOCP)
            __stop_dial_tracker();
#endif
            __close_dial_flow();
            __set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
        });

        if (!__open_dial_flow()) {
            PUMP_ERR_LOG("transport::tls_dialer::start: open flow failed");
            return ERROR_FAULT;
        }

        if (!__start_dial_timer(pump_bind(&tls_dialer::on_timeout, shared_from_this()))) {
            PUMP_ERR_LOG("transport::tls_dialer::start: start connect timer failed");
            return ERROR_FAULT;
        }

        if (flow_->post_connect(remote_address_) != flow::FLOW_ERR_NO) {
            PUMP_ERR_LOG("transport::tls_dialer::start: flow post_connect failed");
            return ERROR_FAULT;
        }

#if !defined(PUMP_HAVE_IOCP)
        if (!__start_dial_tracker(shared_from_this())) {
            PUMP_ERR_LOG("transport::tls_dialer::start: start tracker failed");
            return ERROR_FAULT;
        }
#endif
        __set_status(TRANSPORT_STARTING, TRANSPORT_STARTED);

        cleanup.clear();

        return ERROR_OK;
    }

    void tls_dialer::stop() {
        // When stopping done, tracker event will trigger stopped callback.
        if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
            __stop_dial_timer();
            __close_dial_flow();
            __post_channel_event(shared_from_this(), 0);
            return;
        } else if (__set_status(TRANSPORT_HANDSHAKING, TRANSPORT_STOPPING)) {
            PUMP_ASSERT(handshaker_);
            handshaker_->stop();
        }

        // If in timeouting status at the moment, it means that dialer is timeout
        // but hasn't triggered tracker event callback yet. So we just set it to
        // stopping status, then tracker event will trigger stopped callabck.
        if (__set_status(TRANSPORT_TIMEOUTING, TRANSPORT_STOPPING)) {
            return;
        }
    }

#if defined(PUMP_HAVE_IOCP)
    void tls_dialer::on_send_event(net::iocp_task_ptr iocp_task) {
#else
    void tls_dialer::on_send_event() {
#endif
        // Stop dial timer
        __stop_dial_timer();

#if !defined(PUMP_HAVE_IOCP)
        __stop_dial_tracker();
#endif
        auto flow = flow_.get();
        address local_address, remote_address;
#if defined(PUMP_HAVE_IOCP)
        bool success = (flow->connect(iocp_task, &local_address, &remote_address) == 0);
#else
        bool success = (flow->connect(&local_address, &remote_address) == 0);
#endif
        auto next_status = success ? TRANSPORT_HANDSHAKING : TRANSPORT_ERROR;
        if (!__set_status(TRANSPORT_STARTING, next_status) &&
            !__set_status(TRANSPORT_STARTED, next_status)) {
            PUMP_DEBUG_LOG(
                "transport::tls_dialer::on_send_event: dialer had stopped or timeout");
            __close_dial_flow();
            __trigger_interrupt_callbacks();
            return;
        }

        if (PUMP_LIKELY(success)) {
            // If handshaker is started error, handshaked callback will be triggered. So
            // we do nothing at here when started error. But if dialer stopped befere
            // here, we shuold stop handshaking.
            handshaker_.reset(object_create<tls_handshaker>(),
                              object_delete<tls_handshaker>);
            handshaker_->init(
                flow->unbind(), true, xcred_, local_address, remote_address);

            tls_handshaker::tls_handshaker_callbacks tls_cbs;
            tls_cbs.handshaked_cb =
                pump_bind(&tls_dialer::on_handshaked, shared_from_this(), _1, _2);
            tls_cbs.stopped_cb =
                pump_bind(&tls_dialer::on_handshake_stopped, shared_from_this(), _1);
            if (handshaker_->start(get_service(), handshake_timeout_, tls_cbs)) {
                if (!__is_status(TRANSPORT_HANDSHAKING)) {
                    PUMP_DEBUG_LOG(
                        "transport::tls_acceptor::on_read_event: dialer had stopped "
                        "after starting handshaker");
                    handshaker_->stop();
                }
                return;
            } else if (__set_status(TRANSPORT_HANDSHAKING, TRANSPORT_ERROR)) {
                PUMP_ERR_LOG(
                    "transport::tls_dialer::on_send_event: handshaker start failed");
                handshaker_.reset();
            }
        } else {
            PUMP_DEBUG_LOG("transport::tls_dialer::on_send_event: dial failed");
            __close_dial_flow();
        }

        base_transport_sptr tls_transport;
        cbs_.dialed_cb(tls_transport, false);
    }

    void tls_dialer::on_timeout(tls_dialer_wptr wptr) {
        PUMP_LOCK_WPOINTER(dialer, wptr);
        if (!dialer) {
            PUMP_DEBUG_LOG("transport::tls_dialer::on_timeout: dialer invalid");
            return;
        }

        if (dialer->__set_status(TRANSPORT_STARTED, TRANSPORT_TIMEOUTING)) {
            PUMP_WARN_LOG("transport::tls_dialer::on_timeout: dialer timeout");
#if defined(PUMP_HAVE_IOCP)
            dialer->__close_dial_flow();
#else
            dialer->__stop_dial_tracker();
            dialer->__post_channel_event(dialer_locker, 0);
#endif
        }
    }

    void tls_dialer::on_handshaked(tls_dialer_wptr wptr,
                                   tls_handshaker_ptr handshaker,
                                   bool succ) {
        PUMP_LOCK_WPOINTER(dialer, wptr);
        if (!dialer) {
            PUMP_WARN_LOG("transport::tls_dialer::on_handshaked: dialer invalid");
            handshaker->stop();
            return;
        }

        if (dialer->__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED)) {
            dialer->cbs_.stopped_cb();
        } else if (dialer->__set_status(TRANSPORT_HANDSHAKING, TRANSPORT_FINISHED)) {
            tls_transport_sptr tls_transport;
            if (PUMP_LIKELY(succ)) {
                auto flow = handshaker->unlock_flow();
                auto local_address = handshaker->get_local_address();
                auto remote_address = handshaker->get_remote_address();

                tls_transport = tls_transport::create();
                tls_transport->init(flow, local_address, remote_address);
            }

            base_transport_sptr transport = tls_transport;
            dialer->cbs_.dialed_cb(transport, succ);
        }

        dialer->handshaker_.reset();
    }

    void tls_dialer::on_handshake_stopped(tls_dialer_wptr wptr,
                                          tls_handshaker_ptr handshaker) {
        PUMP_LOCK_WPOINTER(dialer, wptr);
        if (!dialer) {
            PUMP_WARN_LOG("transport::tls_dialer::on_handshake_stopped: dialer invalid");
            return;
        }

        dialer->handshaker_.reset();

        dialer->__trigger_interrupt_callbacks();
    }

    bool tls_dialer::__open_dial_flow() {
        // Setup flow
        PUMP_ASSERT(!flow_);
        flow_.reset(object_create<flow::flow_tcp_dialer>(),
                    object_delete<flow::flow_tcp_dialer>);

        if (flow_->init(shared_from_this(), local_address_) != flow::FLOW_ERR_NO) {
            PUMP_ERR_LOG("transport::tls_dialer::__open_dial_flow: flow init failed");
            return false;
        }

        // Set channel fd
        poll::channel::__set_fd(flow_->get_fd());

        return true;
    }

    base_transport_sptr tls_sync_dialer::dial(service_ptr sv,
                                              const address &local_address,
                                              const address &remote_address,
                                              int64 connect_timeout,
                                              int64 handshake_timeout) {
        if (dialer_) {
            return base_transport_sptr();
        }

        dialer_callbacks cbs;
        cbs.dialed_cb =
            pump_bind(&tls_sync_dialer::on_dialed, shared_from_this(), _1, _2);
        cbs.timeout_cb = pump_bind(&tls_sync_dialer::on_timeouted, shared_from_this());
        cbs.stopped_cb = pump_bind(&tls_sync_dialer::on_stopped);

        dialer_ = tls_dialer::create(
            local_address, remote_address, connect_timeout, handshake_timeout);
        if (dialer_->start(sv, cbs) != ERROR_OK) {
            return base_transport_sptr();
        }

        return dial_promise_.get_future().get();
    }

    void tls_sync_dialer::on_dialed(tls_sync_dialer_wptr wptr,
                                    base_transport_sptr &transp,
                                    bool succ) {
        PUMP_LOCK_WPOINTER(dialer, wptr);
        if (!dialer) {
            return;
        }

        dialer->dial_promise_.set_value(transp);
    }

    void tls_sync_dialer::on_timeouted(tls_sync_dialer_wptr wptr) {
        PUMP_LOCK_WPOINTER(dialer, wptr);
        if (!dialer) {
            return;
        }

        dialer->dial_promise_.set_value(base_transport_sptr());
    }

    void tls_sync_dialer::on_stopped() {
        PUMP_ASSERT(false);
    }

}  // namespace transport
}  // namespace pump
