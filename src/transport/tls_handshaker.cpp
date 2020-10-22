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

#include "pump/transport/tls_handshaker.h"

namespace pump {
namespace transport {

    const int32 TLS_HANDSHAKE_DONE = 0;
    const int32 TLS_HANDSHAKE_DOING = 1;
    const int32 TLS_HANDSHAKE_ERROR = 2;

    tls_handshaker::tls_handshaker() noexcept
        : base_channel(TLS_HANDSHAKER, nullptr, -1) {
    }

    void tls_handshaker::init(int32 fd,
                              bool client,
                              void_ptr xcred,
                              const address &local_address,
                              const address &remote_address) {
        local_address_ = local_address;
        remote_address_ = remote_address;

        PUMP_DEBUG_CHECK(__open_flow(fd, xcred, client));
    }

    bool tls_handshaker::start(service_ptr sv,
                               int64 timeout,
                               const tls_handshaker_callbacks &cbs) {
        if (!flow_) {
            PUMP_ERR_LOG("transport::tls_handshaker::start: flow invalid");
            return false;
        }

        if (!sv) {
            PUMP_ERR_LOG("transport::tls_handshaker::start: service invalid");
            return false;
        }

        if (!cbs.handshaked_cb || !cbs.stopped_cb) {
            PUMP_ERR_LOG("transport::tcp_acceptor::start: callbacks invalid");
            return false;
        }

        if (!__set_status(TRANSPORT_INITED, TRANSPORT_STARTING)) {
            PUMP_ERR_LOG(
                "transport::tls_handshaker::start: handshaker had be started before");
            return false;
        }

        // Callbacks
        cbs_ = cbs;

        // Service
        __set_service(sv);

        toolkit::defer cleanup([&]() {
            __set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
            __close_flow();
            __stop_handshake_timer();
        });

        // Flow init handshake state
        // If this is client side, tls flow will prepare handshake data to send.
        if (flow_->handshake() == flow::FLOW_ERR_ABORT) {
            PUMP_WARN_LOG("transport::tls_handshaker::start: flow handshake failed");
            return false;
        }

#if !defined(PUMP_HAVE_IOCP)
        // New channel tracker
        tracker_.reset(
            object_create<poll::channel_tracker>(shared_from_this(), poll::TRACK_NONE),
            object_delete<poll::channel_tracker>);
#endif
        // Start handshake timeout timer
        if (!__start_handshake_timer(timeout)) {
            PUMP_WARN_LOG("transport::tls_handshaker::start: start timer failed");
            return false;
        }

        // If this is server side, we will start to read handshake data.
        // If this is client side, there is handshake data to send at first time.
        if (flow_->has_data_to_send()) {
            if (flow_->want_to_send() != flow::FLOW_ERR_NO) {
                PUMP_WARN_LOG("transport::tls_handshaker::start: flow want_to_send failed");
                return false;
            }

#if !defined(PUMP_HAVE_IOCP)
            tracker_->set_event(poll::TRACK_SEND);
            if (!get_service()->add_channel_tracker(tracker_, WRITE_POLLER)) {
                PUMP_WARN_LOG("transport::tls_handshaker::start: add_send_tracker failed");
                return false;
            }
#endif
        } else {
#if defined(PUMP_HAVE_IOCP)
            if (flow_->want_to_read() != flow::FLOW_ERR_NO) {
                PUMP_WARN_LOG("transport::tls_handshaker::start: flow want_to_send failed");
                return false;
            }
#else
            tracker_->set_event(poll::TRACK_READ);
            if (!get_service()->add_channel_tracker(tracker_, WRITE_POLLER)) {
                PUMP_WARN_LOG("transport::tls_handshaker::start: add_read_tracker failed");
                return false;
            }
#endif
        }

        __set_status(TRANSPORT_STARTING, TRANSPORT_STARTED);

        cleanup.clear();

        return true;
    }

    void tls_handshaker::stop() {
        if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
            __close_flow();
            return;
        }

        if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING) ||
            __set_status(TRANSPORT_TIMEOUTING, TRANSPORT_STOPPING)) {
            return;
        }
    }

#if defined(PUMP_HAVE_IOCP)
    void tls_handshaker::on_read_event(void_ptr iocp_task) {
#else
    void tls_handshaker::on_read_event() {
#endif
        auto flow = flow_.get();

#if defined(PUMP_HAVE_IOCP)
        if (flow->read_from_net(iocp_task) == flow::FLOW_ERR_ABORT) {
#else
        if (flow->read_from_net() == flow::FLOW_ERR_ABORT) {
#endif
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING)) {
                __handshake_finished();
            }
        } else {
            __process_handshake(flow);
        }
    }

#if defined(PUMP_HAVE_IOCP)
    void tls_handshaker::on_send_event(void_ptr iocp_task) {
#else
    void tls_handshaker::on_send_event() {
#endif
        auto flow = flow_.get();

#if defined(PUMP_HAVE_IOCP)
        auto ret = flow->send_to_net(iocp_task);
#else
        auto ret = flow->send_to_net();
#endif
        if (ret == flow::FLOW_ERR_ABORT) {
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING)) {
                __handshake_finished();
            }
            return;
        } else if (ret == flow::FLOW_ERR_AGAIN) {
#if !defined(PUMP_HAVE_IOCP)
            __start_handshake_tracker();
#endif
        } else {
            __process_handshake(flow);
        }
    }

    void tls_handshaker::on_timeout(tls_handshaker_wptr wptr) {
        PUMP_LOCK_WPOINTER(handshaker, wptr);
        if (!handshaker) {
            PUMP_ERR_LOG("transport::tls_handshaker::on_timeout: handshaker invalid");
            return;
        }

        if (handshaker->__set_status(TRANSPORT_STARTED, TRANSPORT_TIMEOUTING)) {
            handshaker->__close_flow();
        }
    }

    bool tls_handshaker::__open_flow(int32 fd, void_ptr xcred, bool is_client) {
        // Setup flow
        PUMP_ASSERT(!flow_);
        flow_.reset(object_create<flow::flow_tls>(), object_delete<flow::flow_tls>);

        poll::channel_sptr ch = shared_from_this();
        if (flow_->init(ch, fd, xcred, is_client) != flow::FLOW_ERR_NO) {
            PUMP_WARN_LOG("transport::tls_handshaker::__open_flow: flow init failed");
            return false;
        }

        // Set channel fd
        poll::channel::__set_fd(fd);

        return true;
    }

    void tls_handshaker::__process_handshake(flow::flow_tls_ptr flow) {
        if (flow->handshake() != flow::FLOW_ERR_NO) {
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_ERROR)) {
                __handshake_finished();
            }
            PUMP_ERR_LOG(
                "transport::tls_handshaker::__process_handshake: flow handshake failed");
            return;
        }

#if !defined(PUMP_HAVE_IOCP)
        auto tracker = tracker_.get();
#endif
        if (flow->has_data_to_send()) {
#if defined(PUMP_HAVE_IOCP)
            if (flow->want_to_send() != flow::FLOW_ERR_NO &&
                __set_status(TRANSPORT_STARTED, TRANSPORT_ERROR)) {
                __post_channel_event(shared_from_this(), 0);
            }
#else
            tracker->set_event(poll::TRACK_SEND);

            PUMP_ASSERT(tracker->is_started());
            PUMP_DEBUG_CHECK(tracker->set_tracked(true));
#endif
            return;
        }

        if (!flow->is_handshaked()) {
#if defined(PUMP_HAVE_IOCP)
            if (flow->want_to_read() != flow::FLOW_ERR_NO &&
                __set_status(TRANSPORT_STARTED, TRANSPORT_ERROR))
                __post_channel_event(shared_from_this(), 0);
#else
            tracker->set_event(poll::TRACK_READ);

            PUMP_ASSERT(tracker->is_started());
            PUMP_DEBUG_CHECK(tracker->set_tracked(true));
#endif
            return;
        }

        if (__set_status(TRANSPORT_STARTED, TRANSPORT_FINISHED)) {
            __handshake_finished();
        }
    }

    bool tls_handshaker::__start_handshake_timer(int64 timeout) {
        if (timeout <= 0)
            return true;

        PUMP_ASSERT(!timer_);
        time::timer_callback cb =
            pump_bind(&tls_handshaker::on_timeout, shared_from_this());
        timer_ = time::timer::create_instance(timeout, cb);

        return get_service()->start_timer(timer_);
    }

    void tls_handshaker::__stop_handshake_timer() {
        if (timer_) {
            timer_->stop();
        }
    }

#if !defined(PUMP_HAVE_IOCP)
    void tls_handshaker::__start_handshake_tracker() {
        PUMP_LOCK_SPOINTER(tracker, tracker_);
        if (!tracker) {
            PUMP_WARN_LOG("transport::tls_handshaker::__stop_tracker: tracker no exists");
            return;
        }

        PUMP_DEBUG_CHECK(get_service()->resume_channel_tracker(tracker, WRITE_POLLER));
    }

    void tls_handshaker::__stop_handshake_tracker() {
        PUMP_LOCK_SPOINTER(tracker, tracker_);
        if (!tracker) {
            PUMP_WARN_LOG("transport::tls_handshaker::__stop_tracker: tracker no exists");
            return;
        }

        if (!tracker->is_started()) {
            PUMP_WARN_LOG(
                "transport::tls_handshaker::__stop_tracker: tracker not started");
            return;
        }

        PUMP_DEBUG_CHECK(
            get_service()->remove_channel_tracker(tracker_locker, WRITE_POLLER));
    }
#endif

    void tls_handshaker::__handshake_finished() {
        // Stop handshake timer
        __stop_handshake_timer();

#if !defined(PUMP_HAVE_IOCP)
        __stop_handshake_tracker();
#endif
        if (__is_status(TRANSPORT_FINISHED)) {
            cbs_.handshaked_cb(this, true);
        } else if (__is_status(TRANSPORT_ERROR)) {
            cbs_.handshaked_cb(this, false);
        } else if (__set_status(TRANSPORT_TIMEOUTING, TRANSPORT_TIMEOUTED)) {
            cbs_.handshaked_cb(this, false);
        } else if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_DISCONNECTED)) {
            cbs_.handshaked_cb(this, false);
        } else if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED)) {
            cbs_.stopped_cb(this);
        }
        
        __close_flow();
    }

}  // namespace transport
}  // namespace pump
