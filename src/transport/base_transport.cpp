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

    void base_transport::on_channel_event(int32_t ev) {
        __interrupt_and_trigger_callbacks();
    }

    int32_t base_transport::__change_read_state(int32_t state) {
        int32_t current_state = read_state_.load();
        if (current_state >= READ_PENDING) {
            if (!read_state_.compare_exchange_strong(current_state, state)) {
                return READ_INVALID;
            }
            return current_state;
        }

        current_state = READ_NONE;
        if (read_state_.compare_exchange_strong(current_state, state)) {
            return current_state;
        }

        return READ_INVALID;
    }

    void base_transport::__interrupt_and_trigger_callbacks() {
        if (__set_state(TRANSPORT_DISCONNECTING, TRANSPORT_DISCONNECTED)) {
            __stop_read_tracker();
            __stop_send_tracker();
            __close_transport_flow();
            cbs_.disconnected_cb();

        } else if (__set_state(TRANSPORT_STOPPING, TRANSPORT_STOPPED)) {
            __stop_read_tracker();
            __stop_send_tracker();
            __close_transport_flow();
            cbs_.stopped_cb();

        }
    }

}  // namespace transport
}  // namespace pump
