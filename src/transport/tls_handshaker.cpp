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

#include "pump/memory.h"
#include "pump/transport/tls_handshaker.h"

namespace pump {
namespace transport {

tls_handshaker::tls_handshaker() pump_noexcept
  : base_channel(transport_tls_handshaker, nullptr, -1) {
}

tls_handshaker::~tls_handshaker() {
    if (tracker_ && tracker_->get_poller() != nullptr) {
        tracker_->get_poller()->uninstall_channel_tracker(tracker_);
    }
}

bool tls_handshaker::init(
    pump_socket fd,
    bool client,
    tls_credentials xcred,
    const address &local_address,
    const address &remote_address) {
    // Set addresses.
    local_address_ = local_address;
    remote_address_ = remote_address;

    // Open flow.
    if (!__open_flow(client, fd, xcred)) {
        pump_debug_log("open tls handshaker's flow falied");
        net::close(fd);
        return false;
    }

    return true;
}

bool tls_handshaker::start(
    service *sv,
    uint64_t timeout_ns,
    const tls_handshaker_callbacks &cbs) {
    if (sv == nullptr) {
        pump_debug_log("service invalid");
        return false;
    }

    if (!cbs.handshaked_cb || !cbs.stopped_cb) {
        pump_debug_log("callbacks invalid");
        return false;
    }

    if (!flow_) {
        pump_debug_log("tls handshaker's flow invalid");
        return false;
    }

    if (!__set_state(state_none, state_starting)) {
        pump_debug_log("tls handshaker already started before");
        return false;
    }

    do {
        cbs_ = cbs;

        __set_service(sv);

        // Flow init handshake
        auto phase = flow_->handshake();
        if (phase == tls_handshake_error) {
            pump_debug_log("tls flow handshake failed");
            break;
        }

        // Start handshake timeout timer
        if (!__start_handshake_timer(timeout_ns)) {
            pump_debug_log("start tls handshaker's timer failed");
            break;
        }

        // New channel tracker
        tracker_.reset(
            object_create<poll::channel_tracker>(
                shared_from_this(),
                poll::track_none),
            object_delete<poll::channel_tracker>);
        if (!tracker_) {
            pump_warn_log("new tls handshaker's tracker object failed");
            break;
        }
        // Start tracker.
        if (phase == tls_handshake_send) {
            tracker_->set_expected_event(poll::track_send);
        } else {
            tracker_->set_expected_event(poll::track_read);
        }

        auto poller = get_service()->get_poller(send_pid);
        if (poller == nullptr || !poller->install_channel_tracker(tracker_)) {
            pump_debug_log("install tls handshaker's tracker failed");
            break;
        }

        if (__set_state(state_starting, state_started)) {
            return true;
        }
    } while (false);

    __set_state(state_starting, state_error);
    __stop_handshake_timer();

    return false;
}

void tls_handshaker::stop() {
    if (__set_state(state_started, state_stopping)) {
        __post_channel_event(shared_from_this(), channel_event_disconnected);
    } else if (__set_state(state_disconnecting, state_stopping) ||
               __set_state(state_timeouting, state_stopping)) {
        // Do nothing.
    }
}

void tls_handshaker::on_channel_event(int32_t ev, void *arg) {
    __handshake_finished();
}

void tls_handshaker::on_read_event() {
    // Wait starting end
    while (__is_state(state_starting, std::memory_order_relaxed)) {
        //pump_debug_log("tls handshaker starting, wait");
    }

    __process_handshake();
}

void tls_handshaker::on_send_event() {
    // Wait starting end
    while (__is_state(state_starting, std::memory_order_relaxed)) {
        //pump_debug_log("tls handshaker starting, wait");
    }

    __process_handshake();
}

void tls_handshaker::on_timeout(tls_handshaker_wptr wptr) {
    auto handshaker = wptr.lock();
    if (handshaker) {
        if (handshaker->__set_state(state_starting, state_timeouting) ||
            handshaker->__set_state(state_started, state_timeouting)) {
            handshaker->__post_channel_event(handshaker, channel_event_disconnected);
        }
    }
}

bool tls_handshaker::__open_flow(bool client, pump_socket fd, void *xcred) {
    // Create flow.
    flow_.reset(
        object_create<flow::flow_tls>(),
        object_delete<flow::flow_tls>);
    if (!flow_) {
        pump_warn_log("new tls handshaker's flow object failed");
        return false;
    }

    // Init flow.
    poll::channel_sptr ch = shared_from_this();
    if (!flow_->init(ch, client, fd, xcred)) {
        pump_debug_log("init tls handshaker's flow failed");
        net::close(fd);
        return false;
    }

    // Set channel fd
    poll::channel::__set_fd(fd);

    return true;
}

void tls_handshaker::__process_handshake() {
    switch (flow_->handshake()) {
    case tls_handshake_ok:
        if (__set_state(state_started, state_finished)) {
            __handshake_finished();
        }
        return;
    case tls_handshake_read:
        tracker_->set_expected_event(poll::track_read);
        if (!tracker_->get_poller()->start_channel_tracker(tracker_)) {
            pump_debug_log("start tls handshaker's tracker failed");
            break;
        }
        return;
    case tls_handshake_send:
        tracker_->set_expected_event(poll::track_send);
        if (!tracker_->get_poller()->start_channel_tracker(tracker_)) {
            pump_debug_log("start tls handshaker's tracker failed");
            break;
        }
        return;
    default:
        break;
    }

    // Handshake failed.
    if (__set_state(state_started, state_error)) {
        __handshake_finished();
    }
}

bool tls_handshaker::__start_handshake_timer(uint64_t timeout_ns) {
    if (timeout_ns == 0) {
        return true;
    }

    auto cb = pump_bind(&tls_handshaker::on_timeout, shared_from_this());
    if (!(timer_ = time::timer::create(timeout_ns, cb))) {
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
    pump_assert(tracker_);
    pump_assert(tracker_->get_poller() != nullptr);
    tracker_->get_poller()->uninstall_channel_tracker(tracker_);

    if (__is_state(state_finished)) {
        cbs_.handshaked_cb(this, true);
    } else if (__is_state(state_error)) {
        cbs_.handshaked_cb(this, false);
    } else if (__set_state(state_timeouting, state_timeouted)) {
        cbs_.handshaked_cb(this, false);
    } else if (__set_state(state_disconnecting, state_disconnected)) {
        cbs_.handshaked_cb(this, false);
    } else if (__set_state(state_stopping, state_stopped)) {
        cbs_.stopped_cb(this);
    }
}

}  // namespace transport
}  // namespace pump
