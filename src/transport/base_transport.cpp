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

    void base_transport::on_channel_event(uint32 ev) {
        __interrupt_and_trigger_callbacks();
    }

    uint32 base_transport::__change_read_state(uint32 state) {
        uint32 old_state = read_state_.load();
        if (old_state == READ_ONCE || old_state == READ_LOOP) {
            if (!read_state_.compare_exchange_strong(old_state, state)) {
                return READ_INVALID;
            }
            return old_state;
        }

        old_state = READ_NONE;
        if (read_state_.compare_exchange_strong(old_state, state)) {
            return old_state;
        }

        old_state = READ_PENDING;
        if (read_state_.compare_exchange_strong(old_state, state)) {
            return old_state;
        }

        return READ_INVALID;
    }

    void base_transport::__interrupt_and_trigger_callbacks() {
        if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_DISCONNECTED)) {
            __close_transport_flow();
#if !defined(PUMP_HAVE_IOCP)
            __stop_read_tracker();
            __stop_send_tracker();
#endif
            cbs_.disconnected_cb();
        } else if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED)) {
            __close_transport_flow();
#if !defined(PUMP_HAVE_IOCP)
            __stop_read_tracker();
            __stop_send_tracker();
#endif
            cbs_.stopped_cb();
        }
    }

#if !defined(PUMP_HAVE_IOCP)
    bool base_transport::__start_read_tracker(poll::channel_sptr &&ch) {
        PUMP_LOCK_SPOINTER(tracker, r_tracker_);
        if (PUMP_UNLIKELY(!tracker)) {
            r_tracker_.reset(object_create<poll::channel_tracker>(ch, poll::TRACK_READ),
                             object_delete<poll::channel_tracker>);
            if (!get_service()->add_channel_tracker(r_tracker_, READ_POLLER)) {
                PUMP_WARN_LOG("base_transport::__start_read_tracker: add tracker failed");
                return false;
            }
        } else {
            if (!get_service()->resume_channel_tracker(tracker, READ_POLLER)) {
                PUMP_WARN_LOG("base_transport::__start_read_tracker: resume tracker failed");
                return false;
            }
        }

        return true;
    }

    bool base_transport::__start_send_tracker(poll::channel_sptr &&ch) {
        PUMP_LOCK_SPOINTER(tracker, s_tracker_);
        if (PUMP_UNLIKELY(!tracker)) {
            s_tracker_.reset(object_create<poll::channel_tracker>(ch, poll::TRACK_SEND),
                             object_delete<poll::channel_tracker>);
            if (!get_service()->add_channel_tracker(s_tracker_, WRITE_POLLER)) {
                PUMP_WARN_LOG("base_transport::__start_send_tracker: add tracker failed");
                return false;
            }
        } else {
            if (!get_service()->resume_channel_tracker(tracker, WRITE_POLLER)) {
                PUMP_WARN_LOG("base_transport::__start_send_tracker: resume tracker failed");
                return false;
            }
        }

        return true;
    }

    void base_transport::__stop_read_tracker() {
        PUMP_LOCK_SPOINTER(tracker, r_tracker_);
        if (!tracker) {
            PUMP_WARN_LOG("base_transport::__stop_read_tracker: tracker no exists");
            return;
        }

        if (!tracker->is_started()) {
            PUMP_WARN_LOG("base_transport::__stop_read_tracker: tracker not started");
            return;
        }

        PUMP_DEBUG_CHECK(
            get_service()->remove_channel_tracker(tracker_locker, READ_POLLER));
    }

    void base_transport::__stop_send_tracker() {
        PUMP_LOCK_SPOINTER(tracker, s_tracker_);
        if (!tracker) {
            PUMP_WARN_LOG("base_transport::__stop_send_tracker: tracker no exists");
            return;
        }

        if (!tracker->is_started()) {
            PUMP_WARN_LOG("base_transport::__stop_send_tracker: tracker not started");
            return;
        }

        PUMP_DEBUG_CHECK(
            get_service()->remove_channel_tracker(tracker_locker, WRITE_POLLER));
    }
#endif

}  // namespace transport
}  // namespace pump
