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

    void base_dialer::on_channel_event(uint32 ev) {
        __trigger_interrupt_callbacks();
    }

#if !defined(PUMP_HAVE_IOCP)
    bool base_dialer::__start_dial_tracker(poll::channel_sptr &&ch) {
        if (tracker_) {
            PUMP_WARN_LOG("base_dialer::__start_dial_tracker: tracker exists");
            return false;
        }

        tracker_.reset(object_create<poll::channel_tracker>(ch, poll::TRACK_SEND),
                       object_delete<poll::channel_tracker>);
        if (!get_service()->add_channel_tracker(tracker_, WRITE_POLLER)) {
            PUMP_WARN_LOG("base_dialer::__start_dial_tracker: add tracker failed");
            return false;
        }

        return true;
    }

    void base_dialer::__stop_dial_tracker() {
        PUMP_LOCK_SPOINTER(tracker, tracker_);
        if (!tracker) {
            PUMP_WARN_LOG("base_dialer::__stop_dial_tracker: tracker no exists");
            return;
        }

        if (!tracker->is_started()) {
            PUMP_WARN_LOG("base_dialer::__stop_dial_tracker: tracker not started");
            return;
        }

        PUMP_DEBUG_CHECK(
            get_service()->remove_channel_tracker(tracker_locker, WRITE_POLLER));
    }
#endif

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
        if (__set_status(TRANSPORT_TIMEOUTING, TRANSPORT_TIMEOUTED)) {
            cbs_.timeouted_cb();
        } else if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED)) {
            cbs_.stopped_cb();
        }
    }

}  // namespace transport
}  // namespace pump
