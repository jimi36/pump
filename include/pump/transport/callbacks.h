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

#ifndef pump_transport_callbacks_h
#define pump_transport_callbacks_h

#include "pump/transport/address.h"

namespace pump {
namespace transport {

    class base_transport;
    DEFINE_ALL_POINTER_TYPE(base_transport);

    struct acceptor_callbacks {
        // Accepted callback
        pump_function<void(base_transport_sptr&)> accepted_cb;
        // Acceptor Stopped calloback
        pump_function<void()> stopped_cb;
    };

    struct dialer_callbacks {
        // Dialed callback
        pump_function<void(base_transport_sptr&, bool)> dialed_cb;
        // Dialer timouted callback
        pump_function<void()> timeouted_cb;
        // Dialer stopped callback
        pump_function<void()> stopped_cb;
    };

    struct transport_callbacks {
        // Read callback for tcp and tls
        pump_function<void(c_block_ptr, int32)> read_cb;
        // Read from callback for udp
        pump_function<void(c_block_ptr, int32, const address&)> read_from_cb;
        // Transport disconnected callback
        pump_function<void()> disconnected_cb;
        // Transport stopped callback
        pump_function<void()> stopped_cb;
    };

}  // namespace transport
}  // namespace pump

#endif