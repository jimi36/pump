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

    void base_dialer::on_channel_event(int32_t ev) {
        __trigger_interrupt_callbacks();
    }

    bool base_dialer::__start_dial_tracker(poll::channel_sptr &&ch) {
        if (tracker_) {
            return false;
        }

        tracker_.reset(object_create<poll::channel_tracker>(ch, poll::TRACK_SEND),
                       object_delete<poll::channel_tracker>);
        if (!get_service()->add_channel_tracker(tracker_, SEND_POLLER)) {
            PUMP_WARN_LOG("base_dialer: start tracker failed");
            return false;
        }

        //PUMP_DEBUG_LOG("base_dialer: start tracker");

        return true;
    }

    void base_dialer::__stop_dial_tracker() {
        auto tracker_locker = tracker_;
        if (!tracker_locker) {
            return;
        }

        get_service()->remove_channel_tracker(tracker_locker, SEND_POLLER);

        PUMP_DEBUG_LOG("base_dialer: stop tracker");
    }

    bool base_dialer::__start_dial_timer(const time::timer_callback &cb) {
        if (connect_timeout_ <= 0) {
            return true;
        }

        PUMP_ASSERT(!connect_timer_);
        connect_timer_ = time::timer::create(connect_timeout_, cb);

        return get_service()->start_timer(connect_timer_);
    }

    void base_dialer::__stop_dial_timer() {
        if (connect_timer_) {
            connect_timer_->stop();
        }
    }

    void base_dialer::__trigger_interrupt_callbacks() {
        if (__set_state(TRANSPORT_TIMEOUTING, TRANSPORT_TIMEOUTED)) {
            cbs_.timeouted_cb();
        } else if (__set_state(TRANSPORT_STOPPING, TRANSPORT_STOPPED)) {
            cbs_.stopped_cb();
        }
    }

}  // namespace transport
}  // namespace pump
