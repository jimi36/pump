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
#if !defined(PUMP_HAVE_IOCP)
        __stop_accept_tracker();
#endif
        __close_accept_flow();
    }

    void base_acceptor::on_channel_event(uint32 ev) {
        __trigger_interrupt_callbacks();
    }

#if !defined(PUMP_HAVE_IOCP)
    bool base_acceptor::__start_accept_tracker(poll::channel_sptr &&ch) {
        if (tracker_) {
            PUMP_WARN_LOG("base_acceptor::__start_accept_tracker: tracker exists");
            return false;
        }

        tracker_.reset(object_create<poll::channel_tracker>(ch, poll::TRACK_READ),
                       object_delete<poll::channel_tracker>);
        if (!get_service()->add_channel_tracker(tracker_, READ_POLLER)) {
            PUMP_WARN_LOG("base_acceptor::__start_accept_tracker: add tracker failed");
            return false;
        }

        return true;
    }

    void base_acceptor::__stop_accept_tracker() {
        PUMP_LOCK_SPOINTER(tracker, tracker_);
        if (!tracker) {
            PUMP_WARN_LOG("base_acceptor::__stop_accept_tracker: tracker no exists");
            return;
        }

        if (!tracker->is_started()) {
            PUMP_WARN_LOG("base_acceptor::__stop_accept_tracker: tracker not started");
            return;
        }

        PUMP_DEBUG_CHECK(get_service()->remove_channel_tracker(tracker_, READ_POLLER));
    }
#endif

    void base_acceptor::__trigger_interrupt_callbacks() {
        if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED)) {
            cbs_.stopped_cb();
        }
    }

}  // namespace transport
}  // namespace pump
