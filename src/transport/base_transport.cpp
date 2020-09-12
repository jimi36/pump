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

    bool base_transport::reset_callbacks(const transport_callbacks &cbs) {
        if (!is_started())
            return false;

        PUMP_ASSERT(cbs.read_cb || cbs.read_from_cb);
        PUMP_ASSERT(cbs.disconnected_cb && cbs.stopped_cb);
        cbs_ = cbs;

        return true;
    }

    void base_transport::on_channel_event(uint32 ev) {
        if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_DISCONNECTED))
            cbs_.disconnected_cb();
        else if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED))
            cbs_.stopped_cb();
    }

#if !defined(PUMP_HAVE_IOCP)
    bool base_transport::__start_read_tracker(poll::channel_sptr &&ch) {
        PUMP_LOCK_SPOINTER(tracker, r_tracker_);
        if (tracker == nullptr) {
            r_tracker_.reset(object_create<poll::channel_tracker>(ch, TRACK_READ),
                             object_delete<poll::channel_tracker>);
            if (!get_service()->add_channel_tracker(r_tracker_, READ_POLLER))
                return false;
        } else {
            if (!get_service()->awake_channel_tracker(tracker, READ_POLLER))
                return false;
        }

        return true;
    }

    bool base_transport::__start_send_tracker(poll::channel_sptr &&ch) {
        PUMP_LOCK_SPOINTER(tracker, s_tracker_);
        if (tracker == nullptr) {
            s_tracker_.reset(object_create<poll::channel_tracker>(ch, TRACK_WRITE),
                             object_delete<poll::channel_tracker>);
            if (!get_service()->add_channel_tracker(s_tracker_, WRITE_POLLER))
                return false;
        } else {
            if (!get_service()->awake_channel_tracker(tracker, WRITE_POLLER))
                return false;
        }

        return true;
    }

    void base_transport::__stop_read_tracker() {
        PUMP_LOCK_SPOINTER(tracker, r_tracker_);
        if (tracker && tracker->is_started()) {
            PUMP_DEBUG_CHECK(
                get_service()->remove_channel_tracker(tracker_locker, READ_POLLER));
        }
    }

    void base_transport::__stop_send_tracker() {
        PUMP_LOCK_SPOINTER(tracker, s_tracker_);
        if (tracker && tracker->is_started()) {
            PUMP_DEBUG_CHECK(
                get_service()->remove_channel_tracker(tracker_locker, WRITE_POLLER));
        }
    }
#endif

}  // namespace transport
}  // namespace pump
