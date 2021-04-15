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

    const int32_t TLS_HANDSHAKE_DONE = 0;
    const int32_t TLS_HANDSHAKE_DOING = 1;
    const int32_t TLS_HANDSHAKE_ERROR = 2;

    tls_handshaker::tls_handshaker() noexcept
      : base_channel(TLS_HANDSHAKER, nullptr, -1) {
    }

    void tls_handshaker::init(
        pump_socket fd,
        bool client,
        void *xcred,
        const address &local_address,
        const address &remote_address) {
        local_address_ = local_address;
        remote_address_ = remote_address;

        PUMP_DEBUG_CHECK(__open_flow(fd, xcred, client));
    }

    bool tls_handshaker::start(
        service_ptr sv,
        int64_t timeout,
        const tls_handshaker_callbacks &cbs) {
        if (!flow_) {
            PUMP_ERR_LOG("tls_handshaker: start failed with invalid flow");
            return false;
        }

        if (!sv) {
            PUMP_ERR_LOG("tls_handshaker: start failed with invalid service");
            return false;
        }

        if (!cbs.handshaked_cb || !cbs.stopped_cb) {
            PUMP_ERR_LOG("tls_handshaker: start failed with invalid callbacks");
            return false;
        }

        if (!__set_state(TRANSPORT_INITED, TRANSPORT_STARTING)) {
            PUMP_ERR_LOG("tls_handshaker: start failed with wrong status");
            return false;
        }

        // Callbacks
        cbs_ = cbs;

        // Service
        __set_service(sv);

        toolkit::defer cleanup([&]() {
            __set_state(TRANSPORT_STARTING, TRANSPORT_ERROR);
            __close_flow();
            __stop_handshake_timer();
        });

        // Flow init handshake state
        auto ret = flow_->handshake();
        if (ret == ssl::TLS_HANDSHAKE_ERROR) {
            PUMP_WARN_LOG("tls_handshaker: start failed for flow handshake failed");
            return false;
        }

        // New channel tracker
        tracker_.reset(
            object_create<poll::channel_tracker>(shared_from_this(), poll::TRACK_NONE),
            object_delete<poll::channel_tracker>);

        // Start handshake timeout timer
        if (!__start_handshake_timer(timeout)) {
            PUMP_WARN_LOG("tls_handshaker: start failed for starting handshake timer failed");
            return false;
        }

        // If this is server side, we will start to read handshake data.
        // If this is client side, there is handshake data to send at first time.
        if (ret == ssl::TLS_HANDSHAKE_SEND) {
            tracker_->set_expected_event(poll::TRACK_SEND);
        } else {
            tracker_->set_expected_event(poll::TRACK_READ);
        }
        if (!get_service()->add_channel_tracker(tracker_, SEND_POLLER)) {
            PUMP_WARN_LOG("tls_handshaker: start failed for adding tracker failed");
            return false;
        }

        __set_state(TRANSPORT_STARTING, TRANSPORT_STARTED);

        cleanup.clear();

        return true;
    }

    void tls_handshaker::stop() {
        if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
            __close_flow();
            return;
        }

        if (__set_state(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING) ||
            __set_state(TRANSPORT_TIMEOUTING, TRANSPORT_STOPPING)) {
            return;
        }
    }

    void tls_handshaker::on_read_event() {
        __process_handshake();
    }

    void tls_handshaker::on_send_event() {
        __process_handshake();
    }

    void tls_handshaker::on_timeout(tls_handshaker_wptr wptr) {
        PUMP_LOCK_WPOINTER(handshaker, wptr);
        if (handshaker) {
            if (handshaker->__set_state(TRANSPORT_STARTED, TRANSPORT_TIMEOUTING)) {
                handshaker->__close_flow();
            }
        }
    }

    bool tls_handshaker::__open_flow(pump_socket fd, void *xcred, bool is_client) {
        // Setup flow
        PUMP_ASSERT(!flow_);
        flow_.reset(
            object_create<flow::flow_tls>(), 
            object_delete<flow::flow_tls>);

        poll::channel_sptr ch = shared_from_this();
        if (flow_->init(ch, fd, xcred, is_client) != flow::FLOW_ERR_NO) {
            PUMP_WARN_LOG("tls_handshaker: open flow failed for flow init failed");
            return false;
        }

        // Set channel fd
        poll::channel::__set_fd(fd);

        return true;
    }

    void tls_handshaker::__process_handshake() {
        switch (flow_->handshake()) {
        case ssl::TLS_HANDSHAKE_OK:
            if (__set_state(TRANSPORT_STARTED, TRANSPORT_FINISHED)) {
                __handshake_finished();
            }
            return;
        case ssl::TLS_HANDSHAKE_READ:
            tracker_->set_expected_event(poll::TRACK_READ);
            PUMP_DEBUG_CHECK(tracker_->get_poller()->resume_channel_tracker(tracker_.get()));
            return;
        case ssl::TLS_HANDSHAKE_SEND:
            tracker_->set_expected_event(poll::TRACK_SEND);
            PUMP_DEBUG_CHECK(tracker_->get_poller()->resume_channel_tracker(tracker_.get()));
            return;
        default:
            if (__set_state(TRANSPORT_STARTED, TRANSPORT_ERROR)) {
                __handshake_finished();
            }
            return;
        }
    }

    bool tls_handshaker::__start_handshake_timer(int64_t timeout) {
        if (timeout <= 0) {
            return true;
        }

        PUMP_ASSERT(!timer_);
        time::timer_callback cb = pump_bind(&tls_handshaker::on_timeout, shared_from_this());
        timer_ = time::timer::create(timeout, cb);

        return get_service()->start_timer(timer_);
    }

    void tls_handshaker::__stop_handshake_timer() {
        if (timer_) {
            timer_->stop();
        }
    }

    void tls_handshaker::__start_handshake_tracker() {
        PUMP_ASSERT(tracker_);
        if (!tracker_->get_poller()->resume_channel_tracker(tracker_.get())) {
            PUMP_WARN_LOG("tls_handshaker: start handshake tracker failed for poller resume tracker");
        }
    }

    void tls_handshaker::__stop_handshake_tracker() {
        if (tracker_) {
            tracker_->get_poller()->remove_channel_tracker(tracker_);
        }
    }

    void tls_handshaker::__handshake_finished() {
        // Stop handshake timer
        __stop_handshake_timer();

        __stop_handshake_tracker();

        if (__is_state(TRANSPORT_FINISHED)) {
            cbs_.handshaked_cb(this, true);
        } else if (__is_state(TRANSPORT_ERROR)) {
            cbs_.handshaked_cb(this, false);
        } else if (__set_state(TRANSPORT_TIMEOUTING, TRANSPORT_TIMEOUTED)) {
            cbs_.handshaked_cb(this, false);
        } else if (__set_state(TRANSPORT_DISCONNECTING, TRANSPORT_DISCONNECTED)) {
            cbs_.handshaked_cb(this, false);
        } else if (__set_state(TRANSPORT_STOPPING, TRANSPORT_STOPPED)) {
            cbs_.stopped_cb(this);
        }
        
        __close_flow();
    }

}  // namespace transport
}  // namespace pump
