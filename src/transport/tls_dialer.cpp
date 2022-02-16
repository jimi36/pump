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

#include "pump/transport/tls_dialer.h"
#include "pump/transport/tls_transport.h"

namespace pump {
namespace transport {

tls_dialer::tls_dialer(tls_credentials xcred,
                       const address &local_address,
                       const address &remote_address,
                       int64_t dial_timeout,
                       int64_t handshake_timeout) :
    base_dialer(TLS_DIALER, local_address, remote_address, dial_timeout),
    xcred_(xcred),
    handshake_timeout_(handshake_timeout) {
    if (xcred_ == nullptr) {
        xcred_ = new_client_tls_credentials();
    }
}

tls_dialer::~tls_dialer() {
    __stop_dial_tracker();

    if (flow_ && handshaker_) {
        flow_->unbind();
    }

    delete_tls_credentials(xcred_);
}

error_code tls_dialer::start(service *sv, const dialer_callbacks &cbs) {
    if (sv == nullptr) {
        PUMP_WARN_LOG("service is invalid");
        return ERROR_INVALID;
    }

    if (!cbs.dialed_cb || !cbs.stopped_cb || !cbs.timeouted_cb) {
        PUMP_WARN_LOG("callbacks is invalid");
        return ERROR_INVALID;
    }

    if (xcred_ == nullptr) {
        PUMP_WARN_LOG("tls dialer's cert is invalid");
        return ERROR_INVALID;
    }

    if (!__set_state(TRANSPORT_INITED, TRANSPORT_STARTING)) {
        PUMP_WARN_LOG("tls dialer is already started before");
        return ERROR_FAULT;
    }

    do {
        cbs_ = cbs;

        __set_service(sv);

        if (!__open_dial_flow()) {
            PUMP_WARN_LOG("open tls dialer's flow failed");
            break;
        }

        if (flow_->post_connect(remote_address_) != ERROR_OK) {
            PUMP_WARN_LOG("tls dialer's flow connect failed");
            break;
        }

        if (!__start_dial_timer(
                pump_bind(&tls_dialer::on_timeout, shared_from_this()))) {
            PUMP_WARN_LOG("start tls dialer's timer failed");
            break;
        }

        if (!__start_dial_tracker(shared_from_this())) {
            PUMP_WARN_LOG("start tls dialer's tracker failed");
            break;
        }

        if (__set_state(TRANSPORT_STARTING, TRANSPORT_STARTED)) {
            return ERROR_OK;
        }
    } while (false);

    __stop_dial_timer();
    __set_state(TRANSPORT_STARTING, TRANSPORT_ERROR);

    return ERROR_FAULT;
}

void tls_dialer::stop() {
    // When stopping done, tracker event will trigger stopped callback.
    if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
        __stop_dial_timer();
        __shutdown_dial_flow();
        __post_channel_event(shared_from_this(), 0);
    } else if (__set_state(TRANSPORT_HANDSHAKING, TRANSPORT_STOPPING)) {
        __shutdown_dial_flow();
        __post_channel_event(shared_from_this(), 0);
    } else {
        // If in timeouting status at the moment, it means that dialer is
        // timeout but hasn't triggered tracker event callback yet. So we just
        // set it to stopping status, then tracker event will trigger stopped
        // callabck.
        __set_state(TRANSPORT_TIMEOUTING, TRANSPORT_STOPPING);
    }
}

void tls_dialer::on_send_event() {
    // Stop dial timer.
    __stop_dial_timer();
    // Stop dial tracker.
    __stop_dial_tracker();

    address local_address, remote_address;
    bool success = (flow_->connect(&local_address, &remote_address) == 0);
    auto next_status = success ? TRANSPORT_HANDSHAKING : TRANSPORT_ERROR;
    if (!__set_state(TRANSPORT_STARTING, next_status) &&
        !__set_state(TRANSPORT_STARTED, next_status)) {
        PUMP_WARN_LOG(
            "tls dialer is finished, but it is already stopped or timeout");
        return;
    }

    do {
        if (!success) {
            PUMP_WARN_LOG("tls dialer is failed");
            break;
        }

        handshaker_.reset(object_create<tls_handshaker>(),
                          object_delete<tls_handshaker>);
        if (!handshaker_) {
            PUMP_WARN_LOG("new tls handshaker object failed");
            if (__set_state(TRANSPORT_HANDSHAKING, TRANSPORT_ERROR)) {
                break;
            }
            return;
        }

        pump_socket fd = flow_->get_fd();
        if (!handshaker_
                 ->init(fd, true, xcred_, local_address, remote_address)) {
            PUMP_WARN_LOG("init tls handshaker failed");
            if (__set_state(TRANSPORT_HANDSHAKING, TRANSPORT_ERROR)) {
                break;
            }
            return;
        }

        tls_handshaker::tls_handshaker_callbacks tls_cbs;
        tls_cbs.handshaked_cb =
            pump_bind(&tls_dialer::on_handshaked, shared_from_this(), _1, _2);
        tls_cbs.stopped_cb = pump_bind(&tls_dialer::on_handshake_stopped,
                                       shared_from_this(),
                                       _1);
        if (!handshaker_->start(get_service(), handshake_timeout_, tls_cbs)) {
            PUMP_WARN_LOG("start tls handshaker failed");
            if (__set_state(TRANSPORT_HANDSHAKING, TRANSPORT_ERROR)) {
                break;
            }
        }
        return;
    } while (false);

    base_transport_sptr tls_transport;
    cbs_.dialed_cb(tls_transport, false);
}

void tls_dialer::on_timeout(tls_dialer_wptr wptr) {
    auto dialer = wptr.lock();
    if (dialer) {
        if (dialer->__set_state(TRANSPORT_STARTED, TRANSPORT_TIMEOUTING)) {
            PUMP_WARN_LOG("tcp dialer is timeout");
            dialer->__post_channel_event(dialer, 0);
        }
    }
}

void tls_dialer::on_handshaked(tls_dialer_wptr wptr,
                               tls_handshaker *handshaker,
                               bool succ) {
    auto dialer = wptr.lock();
    if (dialer) {
        if (dialer->__set_state(TRANSPORT_HANDSHAKING, TRANSPORT_FINISHED)) {
            tls_transport_sptr tls_transport;
            if (pump_likely(succ)) {
                tls_transport = tls_transport::create();
                if (tls_transport) {
                    tls_transport->init(handshaker->unlock_flow(),
                                        handshaker->get_local_address(),
                                        handshaker->get_remote_address());
                } else {
                    PUMP_WARN_LOG("new tls transport object failed");
                    succ = false;
                }
            }

            base_transport_sptr transport = tls_transport;
            dialer->cbs_.dialed_cb(transport, succ);
        }
    }
}

void tls_dialer::on_handshake_stopped(tls_dialer_wptr wptr,
                                      tls_handshaker *handshaker) {}

bool tls_dialer::__open_dial_flow() {
    // Init tls dialer flow.
    flow_.reset(object_create<flow::flow_tcp_dialer>(),
                object_delete<flow::flow_tcp_dialer>);
    if (!flow_) {
        PUMP_WARN_LOG("new tls dialer's flow object failed");
        return false;
    }
    if (flow_->init(shared_from_this(), local_address_) != ERROR_OK) {
        PUMP_WARN_LOG("init tls dialer's flow failed");
        return false;
    }

    // Set channel fd
    poll::channel::__set_fd(flow_->get_fd());

    return true;
}

void tls_dialer::__shutdown_dial_flow() {
    if (flow_) {
        flow_->shutdown(SHUT_RDWR);
    }
}

void tls_dialer::__close_dial_flow() {
    if (flow_) {
        flow_->close();
    }
}

base_transport_sptr tls_sync_dialer::dial(service *sv,
                                          const address &local_address,
                                          const address &remote_address,
                                          int64_t connect_timeout,
                                          int64_t handshake_timeout) {
    if (dialer_) {
        return base_transport_sptr();
    }

    dialer_callbacks cbs;
    cbs.dialed_cb =
        pump_bind(&tls_sync_dialer::on_dialed, shared_from_this(), _1, _2);
    cbs.timeouted_cb =
        pump_bind(&tls_sync_dialer::on_timeouted, shared_from_this());
    cbs.stopped_cb = pump_bind(&tls_sync_dialer::on_stopped);

    dialer_ = tls_dialer::create(local_address,
                                 remote_address,
                                 connect_timeout,
                                 handshake_timeout);
    if (!dialer_ || dialer_->start(sv, cbs) != ERROR_OK) {
        return base_transport_sptr();
    }

    return dial_promise_.get_future().get();
}

void tls_sync_dialer::on_dialed(tls_sync_dialer_wptr wptr,
                                base_transport_sptr &transp,
                                bool succ) {
    auto dialer = wptr.lock();
    if (dialer) {
        dialer->dial_promise_.set_value(transp);
    }
}

void tls_sync_dialer::on_timeouted(tls_sync_dialer_wptr wptr) {
    auto dialer = wptr.lock();
    if (dialer) {
        dialer->dial_promise_.set_value(base_transport_sptr());
    }
}

void tls_sync_dialer::on_stopped() {
    PUMP_ASSERT(false);
}

}  // namespace transport
}  // namespace pump
