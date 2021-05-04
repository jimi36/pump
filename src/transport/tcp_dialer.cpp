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

#include "pump/transport/tcp_dialer.h"
#include "pump/transport/tcp_transport.h"

namespace pump {
namespace transport {

    tcp_dialer::tcp_dialer(
        const address &local_address,
        const address &remote_address,
        int64_t timeout) noexcept
      : base_dialer(TCP_DIALER, local_address, remote_address, timeout) {
    }

    tcp_dialer::~tcp_dialer() {
        __stop_dial_tracker();
    }

    error_code tcp_dialer::start(
        service *sv, 
        const dialer_callbacks &cbs) {
        PUMP_DEBUG_FAILED(
            !__set_state(TRANSPORT_INITED, TRANSPORT_STARTING), 
            "tcp_dialer: start failed for transport state incorrect",
            return ERROR_INVALID);

        bool ret = false;
        toolkit::defer cleanup([&]() {
            if (ret) {
                __set_state(TRANSPORT_STARTING, TRANSPORT_STARTED);
            } else {
                __set_state(TRANSPORT_STARTING, TRANSPORT_ERROR);
                __stop_dial_timer();
            }
        });

        PUMP_DEBUG_FAILED(
            sv == nullptr, 
            "tcp_dialer: start failed for service invalid",
            return ERROR_INVALID);
        __set_service(sv);

        PUMP_DEBUG_FAILED(
            !cbs.dialed_cb || !cbs.stopped_cb || !cbs.timeouted_cb, 
            "tcp_dialer: start failed for callbacks invalid",
            return ERROR_INVALID);
        cbs_ = cbs;

        if (!__open_dial_flow()) {
            PUMP_DEBUG_LOG("tcp_dialer: start failed for opening flow failed");
            return ERROR_FAULT;
        }

        if (!__start_dial_timer(pump_bind(&tcp_dialer::on_timeout, shared_from_this()))) {
            PUMP_DEBUG_LOG("tcp_dialer: start failed for starting timer failed");
            return ERROR_FAULT;
        }

        if (flow_->post_connect(remote_address_) != ERROR_OK) {
            PUMP_DEBUG_LOG("tcp_dialer: start failed for posting connect failed");
            return ERROR_FAULT;
        }

        if (!__start_dial_tracker(shared_from_this())) {
            PUMP_DEBUG_LOG("tcp_dialer: start failed for starting dial tracker failed");
            return ERROR_FAULT;
        }

        ret = true;

        return ERROR_OK;
    }

    void tcp_dialer::stop() {
        // When stopping done, tracker event will trigger stopped callback.
        if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
            __stop_dial_timer();
            __shutdown_dial_flow();
            __post_channel_event(shared_from_this(), 0);
        } else {
            // If in timeouting status at the moment, it means that dialer is timeout
            // but hasn't triggered tracker event callback yet. So we just set it to
            // stopping status, then tracker event will trigger stopped callabck.
            __set_state(TRANSPORT_TIMEOUTING, TRANSPORT_STOPPING);
        }
    }

    void tcp_dialer::on_send_event() {
        // Stop timeout timer.
        __stop_dial_timer();
        // Stop dial tracker.
        __stop_dial_tracker();

        address local_address, remote_address;
        bool success = (flow_->connect(&local_address, &remote_address) == 0);
        auto next_status = success ? TRANSPORT_FINISHED : TRANSPORT_ERROR;
        if (!__set_state(TRANSPORT_STARTING, next_status) &&
            !__set_state(TRANSPORT_STARTED, next_status)) {
            PUMP_DEBUG_LOG("tcp_dialer: handle send failed for not in started");
            return;
        }

        tcp_transport_sptr tcp_transport;
        if (PUMP_LIKELY(success)) {
            tcp_transport = tcp_transport::create();
            if (tcp_transport) {
                tcp_transport->init(flow_->unbind(), local_address, remote_address);
            } else {
                PUMP_WARN_LOG(
                    "tcp_dialer: handle send failed for creating transport failed");
                success = false;
            }
        } else {
            PUMP_DEBUG_LOG("tcp_dialer: handle send failed for dialing failed");
        }

        base_transport_sptr transport = tcp_transport;
        cbs_.dialed_cb(transport, success);
    }

    void tcp_dialer::on_timeout(tcp_dialer_wptr wptr) {
        auto dialer = wptr.lock();
        if (dialer) {
            if (dialer->__set_state(TRANSPORT_STARTED, TRANSPORT_TIMEOUTING)) {
                PUMP_DEBUG_LOG("tcp_dialer: handle dialing timeouted");
                dialer->__post_channel_event(dialer, 0);
            }
        }
    }

    bool tcp_dialer::__open_dial_flow() {
        // Init tcp dialer flow.
        flow_.reset(
            object_create<flow::flow_tcp_dialer>(),
            object_delete<flow::flow_tcp_dialer>);
        if (!flow_) {
            PUMP_WARN_LOG("tcp_dialer: open flow failed for creating flow failed");
            return false;
        }
        if (flow_->init(shared_from_this(), local_address_) != ERROR_OK) {
            PUMP_DEBUG_LOG("tcp_dialer: open flow failed for initing flow failed");
            return false;
        }

        // Set channel fd
        poll::channel::__set_fd(flow_->get_fd());

        return true;
    }

    void tcp_dialer::__shutdown_dial_flow() {
        if (flow_) {
            flow_->shutdown(SHUT_RDWR);
        }
    }

    void tcp_dialer::__close_dial_flow() {
        if (flow_) {
            flow_->close();
        }
    }

    base_transport_sptr tcp_sync_dialer::dial(
        service *sv,
        const address &local_address,
        const address &remote_address,
        int64_t timeout) {
        if (dialer_) {
            return base_transport_sptr();
        }

        dialer_callbacks cbs;
        cbs.dialed_cb = pump_bind(&tcp_sync_dialer::on_dialed, shared_from_this(), _1, _2);
        cbs.timeouted_cb = pump_bind(&tcp_sync_dialer::on_timeouted, shared_from_this());
        cbs.stopped_cb = pump_bind(&tcp_sync_dialer::on_stopped);

        dialer_ = tcp_dialer::create(local_address, remote_address, timeout);
        if (!dialer_ || dialer_->start(sv, cbs) != ERROR_OK) {
            return base_transport_sptr();
        }

        return dial_promise_.get_future().get();
    }

    void tcp_sync_dialer::on_dialed(
        tcp_sync_dialer_wptr wptr,
        base_transport_sptr &transp,
        bool succ) {
        auto dialer = wptr.lock();
        if (dialer) {
            dialer->dial_promise_.set_value(transp);
        }
    }

    void tcp_sync_dialer::on_timeouted(tcp_sync_dialer_wptr wptr) {
        auto dialer = wptr.lock();
        if (dialer) {
            dialer->dial_promise_.set_value(base_transport_sptr());
        }
    }

    void tcp_sync_dialer::on_stopped() {
        PUMP_ASSERT(false);
    }

}  // namespace transport
}  // namespace pump
