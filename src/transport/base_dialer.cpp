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

#include "pump/transport/base_dialer.h"

namespace pump {
namespace transport {

base_dialer::~base_dialer() {
    __uninstall_dial_tracker();
    __close_dial_flow();
}

void base_dialer::on_channel_event(int32_t ev, void *arg) {
    __trigger_interrupt_callbacks();
}

bool base_dialer::__install_dial_tracker(poll::channel_sptr &&ch) {
    if (tracker_) {
        pump_debug_log("dialer's tracker already exists");
        return false;
    }

    tracker_.reset(
        object_create<poll::channel_tracker>(ch, poll::track_send),
        object_delete<poll::channel_tracker>);
    if (!tracker_) {
        pump_warn_log("new dialer's tracker object failed");
        return false;
    }

    auto poller = get_service()->get_poller(send_pid);
    if (poller == nullptr) {
        pump_debug_log("dialer got invalid send poller");
        return false;
    }
    if (!poller->install_channel_tracker(tracker_)) {
        pump_debug_log("poller install dialer's tracker failed");
        return false;
    }

    return true;
}

void base_dialer::__uninstall_dial_tracker() {
    if (tracker_ && tracker_->get_poller() != nullptr) {
        tracker_->get_poller()->uninstall_channel_tracker(tracker_);
    }
}

bool base_dialer::__start_dial_timer(const time::timer_callback &cb) {
    if (connect_timeout_ns_ == 0) {
        return true;
    }

    connect_timer_ = time::timer::create(connect_timeout_ns_, cb);
    if (!connect_timer_) {
        pump_warn_log("new dialer's timer object failed");
        return false;
    }

    return get_service()->start_timer(connect_timer_);
}

void base_dialer::__stop_dial_timer() {
    if (connect_timer_) {
        connect_timer_->stop();
    }
}

void base_dialer::__trigger_interrupt_callbacks() {
    if (__set_state(state_timeouting, state_timeouted)) {
        __shutdown_dial_flow();
        cbs_.timeouted_cb();
    } else if (__set_state(state_stopping, state_stopped)) {
        __shutdown_dial_flow();
        cbs_.stopped_cb();
    }
}

}  // namespace transport
}  // namespace pump
