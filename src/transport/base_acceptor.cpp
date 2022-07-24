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

#include "pump/transport/base_acceptor.h"

namespace pump {
namespace transport {

base_acceptor::~base_acceptor() {
    __uninstall_accept_tracker();
    __close_accept_flow();
}

void base_acceptor::on_channel_event(int32_t ev, void *arg) {
    __trigger_interrupt_callbacks();
}

bool base_acceptor::__install_accept_tracker(poll::channel_sptr &&ch) {
    if (tracker_) {
        pump_debug_log("acceptor's tracker already exists");
        return false;
    }

    tracker_.reset(
        object_create<poll::channel_tracker>(ch, poll::track_read),
        object_delete<poll::channel_tracker>);
    if (!tracker_) {
        pump_warn_log("new acceptor's tracker object failed");
        return false;
    }

    auto poller = get_service()->get_poller(read_pid);
    if (poller == nullptr) {
        pump_debug_log("acceptor got invalid read poller");
        return false;
    }
    if (!poller->install_channel_tracker(tracker_)) {
        pump_debug_log("poller install acceptor's tracker failed");
        return false;
    }

    return true;
}

bool base_acceptor::__start_accept_tracker() {
    pump_assert(tracker_);
    auto poller = tracker_->get_poller();
    if (poller == nullptr) {
        pump_debug_log("acceptor's tracker not installed");
        return false;
    }
    return poller->start_channel_tracker(tracker_);
}

void base_acceptor::__uninstall_accept_tracker() {
    if (tracker_ && tracker_->get_poller() != nullptr) {
        tracker_->get_poller()->uninstall_channel_tracker(tracker_);
    }
}

void base_acceptor::__trigger_interrupt_callbacks() {
    if (__set_state(state_stopping, state_stopped)) {
        cbs_.stopped_cb();
    }
}

}  // namespace transport
}  // namespace pump
