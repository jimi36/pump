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
    if (__trigger_disconnected_callback() || __trigger_stopped_callback()) {
        // Transport disabled.
    }
}

bool base_transport::__change_read_state(read_state from, read_state to) {
    if (rstate_.compare_exchange_strong(from, to)) {
        return true;
    }
    return false;
}

bool base_transport::__try_triggering_disconnected_callback() {
    if (__set_state(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING)) {
        return __trigger_disconnected_callback();
    }
    return false;
}

bool base_transport::__trigger_disconnected_callback() {
    if (__set_state(TRANSPORT_DISCONNECTING, TRANSPORT_DISCONNECTED)) {
        __shutdown_transport_flow(SHUT_RDWR);
        cbs_.disconnected_cb();
        return true;
    }
    return false;
}

bool base_transport::__trigger_stopped_callback() {
    if (__set_state(TRANSPORT_STOPPING, TRANSPORT_STOPPED)) {
        __shutdown_transport_flow(SHUT_RDWR);
        cbs_.stopped_cb();
        return true;
    }
    return false;
}

}  // namespace transport
}  // namespace pump
