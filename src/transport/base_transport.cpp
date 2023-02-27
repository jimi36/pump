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

#include "pump/transport/base_transport.h"

namespace pump {
namespace transport {

base_transport::~base_transport() {
    __uninstall_read_tracker();
    __uninstall_send_tracker();
    __close_transport_flow();
}

void base_transport::on_channel_event(int32_t ev, void *arg) {
    if (__trigger_disconnected_callback() ||
        __trigger_stopped_callback()) {
    }
}

bool base_transport::__try_triggering_disconnected_callback() {
    if (__set_state(state_started, state_disconnecting)) {
        return __trigger_disconnected_callback();
    }
    return false;
}

bool base_transport::__trigger_disconnected_callback() {
    if (__set_state(state_disconnecting, state_disconnected)) {
        __shutdown_transport_flow(SHUT_RDWR);
        cbs_.disconnected_cb();
        return true;
    }
    return false;
}

bool base_transport::__trigger_stopped_callback() {
    if (__set_state(state_stopping, state_stopped)) {
        __shutdown_transport_flow(SHUT_RDWR);
        cbs_.stopped_cb();
        return true;
    }
    return false;
}

bool base_transport::__install_read_tracker() {
    if (r_tracker_) {
        return false;
    }

    r_tracker_.reset(
        pump_object_create<poll::channel_tracker>(
            shared_from_this(),
            poll::track_none),
        pump_object_destroy<poll::channel_tracker>);
    if (!r_tracker_) {
        pump_debug_log("new transport's read tracker object failed");
        return false;
    }

    auto poller = get_service()->get_poller(read_pid);
    if (poller == nullptr) {
        pump_debug_log("transport got invalid send poller");
        return false;
    }
    if (!poller->install_channel_tracker(r_tracker_)) {
        pump_debug_log("poller install transport's read tracker failed");
        return false;
    }

    r_tracker_->set_expected_event(poll::track_read);

    return true;
}

bool base_transport::__install_send_tracker() {
    if (s_tracker_) {
        return false;
    }

    s_tracker_.reset(
        pump_object_create<poll::channel_tracker>(
            shared_from_this(),
            poll::track_none),
        pump_object_destroy<poll::channel_tracker>);
    if (!s_tracker_) {
        pump_debug_log("new transport's send tracker object failed");
        return false;
    }

    auto poller = get_service()->get_poller(send_pid);
    if (poller == nullptr) {
        pump_debug_log("transport got invalid send poller");
        return false;
    }
    if (!poller->install_channel_tracker(s_tracker_)) {
        pump_debug_log("poller install transport's read tracker failed");
        return false;
    }

    s_tracker_->set_expected_event(poll::track_send);

    return true;
}

void base_transport::__uninstall_read_tracker() {
    if (r_tracker_ && r_tracker_->get_poller() != nullptr) {
        r_tracker_->get_poller()->uninstall_channel_tracker(r_tracker_);
    }
}

void base_transport::__uninstall_send_tracker() {
    if (s_tracker_ && s_tracker_->get_poller() != nullptr) {
        s_tracker_->get_poller()->uninstall_channel_tracker(s_tracker_);
    }
}

bool base_transport::__start_read_tracker() {
    pump_assert(r_tracker_);
    if (r_tracker_->get_poller() != nullptr) {
        return r_tracker_->get_poller()->start_channel_tracker(r_tracker_);
    }
    return false;
}

bool base_transport::__start_send_tracker() {
    pump_assert(s_tracker_);
    if (s_tracker_->get_poller() != nullptr) {
        return s_tracker_->get_poller()->start_channel_tracker(s_tracker_);
    }
    return false;
}

}  // namespace transport
}  // namespace pump
