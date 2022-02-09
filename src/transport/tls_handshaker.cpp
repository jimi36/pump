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

tls_handshaker::tls_handshaker() noexcept : base_channel(TLS_HANDSHAKER, nullptr, -1) {}

tls_handshaker::~tls_handshaker() {
    if (tracker_ && tracker_->get_poller() != nullptr) {
        tracker_->get_poller()->remove_channel_tracker(tracker_);
    }
}

bool tls_handshaker::init(pump_socket fd,
                          bool client,
                          tls_credentials xcred,
                          const address &local_address,
                          const address &remote_address) {
    // Set addresses.
    local_address_ = local_address;
    remote_address_ = remote_address;

    // Open flow.
    if (!__open_flow(client, fd, xcred)) {
        PUMP_WARN_LOG("open tls handshaker's flow falied");
        return false;
    }

    return true;
}

bool tls_handshaker::start(service *sv,
                           int64_t timeout,
                           const tls_handshaker_callbacks &cbs) {
    if (sv == nullptr) {
        PUMP_WARN_LOG("service is invalid");
        return false;
    }

    if (!cbs.handshaked_cb || !cbs.stopped_cb) {
        PUMP_WARN_LOG("callbacks is invalid");
        return false;
    }

    if (!flow_) {
        PUMP_WARN_LOG("tls handshaker's flow is invalid");
        return false;
    }

    if (!__set_state(TRANSPORT_INITED, TRANSPORT_STARTING)) {
        PUMP_WARN_LOG("tls transport is already started before");
        return false;
    }

    do {
        cbs_ = cbs;

        __set_service(sv);

        // Flow init handshake state
        auto handshake_ret = flow_->handshake();
        if (handshake_ret == TLS_HANDSHAKE_ERROR) {
            PUMP_WARN_LOG("tls flow handshake failed");
            break;
        }

        // Start handshake timeout timer
        if (!__start_handshake_timer(timeout)) {
            PUMP_WARN_LOG("starting tls handshaker's timer failed");
            break;
        }

        // New channel tracker
        tracker_.reset(
            object_create<poll::channel_tracker>(shared_from_this(), poll::TRACK_NONE),
            object_delete<poll::channel_tracker>);
        if (!tracker_) {
            PUMP_WARN_LOG("new tls handshaker's tracker object failed");
            break;
        }
        // Start tracker.
        if (handshake_ret == TLS_HANDSHAKE_SEND) {
            tracker_->set_expected_event(poll::TRACK_SEND);
        } else {
            tracker_->set_expected_event(poll::TRACK_READ);
        }
        if (!get_service()->add_channel_tracker(tracker_, SEND_POLLER_ID)) {
            PUMP_WARN_LOG("add tls handshaker's tracker tp service failed");
            break;
        }

        if (__set_state(TRANSPORT_STARTING, TRANSPORT_STARTED)) {
            return true;
        }
    } while (false);

    __set_state(TRANSPORT_STARTING, TRANSPORT_ERROR);
    __stop_handshake_timer();

    return false;
}

void tls_handshaker::stop() {
    if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
        __post_channel_event(shared_from_this(), 0);
    } else if (__set_state(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING) ||
               __set_state(TRANSPORT_TIMEOUTING, TRANSPORT_STOPPING)) {
        // Do nothing.
    }
}

void tls_handshaker::on_channel_event(int32_t ev) {
    __handshake_finished();
}

void tls_handshaker::on_read_event() {
    // If transport is starting, resume tracker.
    if (__is_state(TRANSPORT_STARTING, std::memory_order_relaxed)) {
        PUMP_DEBUG_LOG("tls handshaker is starting, delay to handle read event");
        if (!tracker_->get_poller()->resume_channel_tracker(tracker_.get())) {
            PUMP_WARN_LOG("resume tls handshaker's tracker failed");
            if (__set_state(TRANSPORT_STARTING, TRANSPORT_DISCONNECTING) ||
                __set_state(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING)) {
                __handshake_finished();
            }
        }
        return;
    }

    __process_handshake();
}

void tls_handshaker::on_send_event() {
    // If transport is starting, resume tracker.
    if (__is_state(TRANSPORT_STARTING, std::memory_order_relaxed)) {
        PUMP_DEBUG_LOG("tls handshaker is starting, delay to handle send event");
        if (!tracker_->get_poller()->resume_channel_tracker(tracker_.get())) {
            PUMP_WARN_LOG("resume tls handshaker's tracker failed");
            if (__set_state(TRANSPORT_STARTING, TRANSPORT_DISCONNECTING) ||
                __set_state(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING)) {
                __handshake_finished();
            }
        }
        return;
    }

    __process_handshake();
}

void tls_handshaker::on_timeout(tls_handshaker_wptr wptr) {
    auto handshaker = wptr.lock();
    if (handshaker) {
        if (handshaker->__set_state(TRANSPORT_STARTING, TRANSPORT_TIMEOUTING) ||
            handshaker->__set_state(TRANSPORT_STARTED, TRANSPORT_TIMEOUTING)) {
            handshaker->__post_channel_event(handshaker, 0);
        }
    }
}

bool tls_handshaker::__open_flow(bool client, pump_socket fd, void *xcred) {
    // Create flow.
    flow_.reset(object_create<flow::flow_tls>(), object_delete<flow::flow_tls>);
    if (!flow_) {
        PUMP_WARN_LOG("new tls handshaker's flow object failed");
        return false;
    }

    // Init flow.
    poll::channel_sptr ch = shared_from_this();
    if (flow_->init(ch, client, fd, xcred) != ERROR_OK) {
        PUMP_WARN_LOG("init tls handshaker's flow failed");
        net::close(fd);
        return false;
    }

    // Set channel fd
    poll::channel::__set_fd(fd);

    return true;
}

void tls_handshaker::__process_handshake() {
    switch (flow_->handshake()) {
    case TLS_HANDSHAKE_OK:
        if (__set_state(TRANSPORT_STARTED, TRANSPORT_FINISHED)) {
            __handshake_finished();
        }
        return;
    case TLS_HANDSHAKE_READ:
        tracker_->set_expected_event(poll::TRACK_READ);
        if (!tracker_->get_poller()->resume_channel_tracker(tracker_.get())) {
            PUMP_WARN_LOG("resume tls handshaker's tracker failed");
            break;
        }
        return;
    case TLS_HANDSHAKE_SEND:
        tracker_->set_expected_event(poll::TRACK_SEND);
        if (!tracker_->get_poller()->resume_channel_tracker(tracker_.get())) {
            PUMP_WARN_LOG("resume tls handshaker's tracker failed");
            break;
        }
        return;
    default:
        break;
    }

    // Handshake failed.
    if (__set_state(TRANSPORT_STARTED, TRANSPORT_ERROR)) {
        __handshake_finished();
    }
}

bool tls_handshaker::__start_handshake_timer(int64_t timeout) {
    if (timeout <= 0) {
        return true;
    }

    auto cb = pump_bind(&tls_handshaker::on_timeout, shared_from_this());
    if (!(timer_ = time::timer::create(timeout, cb))) {
        return false;
    }

    return get_service()->start_timer(timer_);
}

void tls_handshaker::__stop_handshake_timer() {
    if (timer_) {
        timer_->stop();
    }
}

void tls_handshaker::__handshake_finished() {
    // Stop handshake timer
    __stop_handshake_timer();

    // Stop tracker.
    PUMP_ASSERT(tracker_);
    PUMP_ASSERT(tracker_->get_poller() != nullptr);
    tracker_->get_poller()->remove_channel_tracker(tracker_);

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
}

}  // namespace transport
}  // namespace pump
