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

    tcp_dialer::tcp_dialer(const address &local_address,
                           const address &remote_address,
                           int64 connect_timeout) noexcept
        : base_dialer(TCP_DIALER, local_address, remote_address, connect_timeout) {
    }

    transport_error tcp_dialer::start(service_ptr sv, const dialer_callbacks &cbs) {
        if (sv == nullptr) {
            PUMP_ERR_LOG("transport::tcp_dialer::start: service invalid");
            return ERROR_INVALID;
        }

        if (!cbs.dialed_cb || !cbs.stopped_cb || !cbs.timeout_cb) {
            PUMP_ERR_LOG("transport::tcp_dialer::start: callbacks invalid");
            return ERROR_INVALID;
        }

        if (!__set_status(TRANSPORT_INITED, TRANSPORT_STARTING)) {
            PUMP_ERR_LOG("transport::tcp_dialer::start: dialer had be started before");
            return ERROR_INVALID;
        }

        // Specifies callbacks
        cbs_ = cbs;

        // Specifies services
        __set_service(sv);

        toolkit::defer cleanup([&]() {
            __close_flow();
#if !defined(PUMP_HAVE_IOCP)
            __stop_tracker();
#endif
            __stop_connect_timer();
            __set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
        });

        if (!__open_flow()) {
            PUMP_ERR_LOG("transport::tcp_dialer::start: open flow failed");
            return ERROR_FAULT;
        }

        if (!__start_connect_timer(
                pump_bind(&tcp_dialer::on_timeout, shared_from_this()))) {
            PUMP_ERR_LOG("transport::tcp_dialer::start: start connect timer failed");
            return ERROR_FAULT;
        }

        if (flow_->want_to_connect(remote_address_) != flow::FLOW_ERR_NO) {
            PUMP_ERR_LOG("transport::tcp_dialer::start: flow want_to_connect failed");
            return ERROR_FAULT;
        }

#if !defined(PUMP_HAVE_IOCP)
        if (!__start_tracker(shared_from_this())) {
            PUMP_ERR_LOG("transport::tcp_dialer::start: start tracker failed");
            return ERROR_FAULT;
        }
#endif
        __set_status(TRANSPORT_STARTING, TRANSPORT_STARTED);

        cleanup.clear();

        return ERROR_OK;
    }

    void tcp_dialer::stop() {
        // When stopping done, tracker event will trigger stopped callback.
        if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
            __close_flow();
#if !defined(PUMP_HAVE_IOCP)
            __stop_tracker();
#endif
            __stop_connect_timer();
            __post_channel_event(shared_from_this(), 0);
            return;
        }

        // If in timeouting status at the moment, it means that dialer is timeout
        // but hasn't triggered tracker event callback yet. So we just set it to
        // stopping status, then tracker event will trigger stopped callabck.
        if (__set_status(TRANSPORT_TIMEOUTING, TRANSPORT_STOPPING))
            return;
    }

#if defined(PUMP_HAVE_IOCP)
    void tcp_dialer::on_send_event(void_ptr iocp_task) {
#else
    void tcp_dialer::on_send_event() {
#endif
        auto flow = flow_.get();
        if (!flow->is_valid()) {
            PUMP_WARN_LOG("transport::tcp_dialer::on_send_event: flow invalid");
            return;
        }

        address local_address, remote_address;

#if defined(PUMP_HAVE_IOCP)
        bool success = (flow->connect(iocp_task, &local_address, &remote_address) == 0);
#else
        bool success = (flow->connect(&local_address, &remote_address) == 0);
#endif
        transport_state next_status = success ? TRANSPORT_FINISHED : TRANSPORT_ERROR;
        if (!__set_status(TRANSPORT_STARTING, next_status) &&
            !__set_status(TRANSPORT_STARTED, next_status)) {
            PUMP_WARN_LOG("transport::tcp_dialer::on_send_event: dialer has stopped");
            return;
        }

#if !defined(PUMP_HAVE_IOCP)
        __stop_tracker();
#endif

        // Stop timer
        __stop_connect_timer();

        tcp_transport_sptr tcp_transport;
        if (success) {
            tcp_transport = tcp_transport::create_instance();
            tcp_transport->init(flow->unbind(), local_address, remote_address);
        } else {
            __close_flow();
        }

        base_transport_sptr transport = tcp_transport;
        cbs_.dialed_cb(transport, success);
    }

    void tcp_dialer::on_timeout(tcp_dialer_wptr wptr) {
        PUMP_LOCK_WPOINTER(dialer, wptr);
        if (dialer == nullptr)
            return;

        if (dialer->__set_status(TRANSPORT_STARTED, TRANSPORT_TIMEOUTING)) {
            dialer->__close_flow();
#if !defined(PUMP_HAVE_IOCP)
            dialer->__stop_tracker();
#endif
            PUMP_WARN_LOG("transport::tcp_dialer::on_timeout: dialer timeout");
            dialer->__post_channel_event(std::move(dialer_locker), 0);
        }
    }

    bool tcp_dialer::__open_flow() {
        // Setup flow
        PUMP_ASSERT(!flow_);
        flow_.reset(object_create<flow::flow_tcp_dialer>(),
                    object_delete<flow::flow_tcp_dialer>);

        if (flow_->init(shared_from_this(), local_address_) != flow::FLOW_ERR_NO) {
            PUMP_ERR_LOG("transport::tcp_dialer::__open_flow: flow init failed");
            return false;
        }

        // Set channel fd
        poll::channel::__set_fd(flow_->get_fd());

        return true;
    }

    base_transport_sptr tcp_sync_dialer::dial(service_ptr sv,
                                              const address &local_address,
                                              const address &remote_address,
                                              int64 connect_timeout) {
        base_transport_sptr transp;

        if (dialer_)
            return base_transport_sptr();

        dialer_callbacks cbs;
        cbs.dialed_cb =
            pump_bind(&tcp_sync_dialer::on_dialed, shared_from_this(), _1, _2);
        cbs.timeout_cb = pump_bind(&tcp_sync_dialer::on_timeouted, shared_from_this());
        cbs.stopped_cb = pump_bind(&tcp_sync_dialer::on_stopped);

        dialer_ =
            tcp_dialer::create_instance(local_address, remote_address, connect_timeout);
        if (dialer_->start(sv, cbs) != ERROR_OK)
            return base_transport_sptr();

        return dial_promise_.get_future().get();
    }

    void tcp_sync_dialer::on_dialed(tcp_sync_dialer_wptr wptr,
                                    base_transport_sptr &transp,
                                    bool succ) {
        PUMP_LOCK_WPOINTER(dialer, wptr);
        if (dialer == nullptr)
            return;

        dialer->dial_promise_.set_value(transp);
    }

    void tcp_sync_dialer::on_timeouted(tcp_sync_dialer_wptr wptr) {
        PUMP_LOCK_WPOINTER(dialer, wptr);
        if (dialer == nullptr)
            return;

        dialer->dial_promise_.set_value(base_transport_sptr());
    }

    void tcp_sync_dialer::on_stopped() {
        PUMP_ASSERT(false);
    }

}  // namespace transport
}  // namespace pump
