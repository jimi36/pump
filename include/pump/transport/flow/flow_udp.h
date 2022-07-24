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

#ifndef pump_transport_flow_udp_h
#define pump_transport_flow_udp_h

#include "pump/transport/flow/flow.h"

namespace pump {
namespace transport {
namespace flow {

class flow_udp : public flow_base {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    flow_udp() pump_noexcept;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~flow_udp() = default;

    /*********************************************************************************
     * Init
     ********************************************************************************/
    bool init(
        poll::channel_sptr &&ch,
        const address &bind_address);

    /*********************************************************************************
     * Read from
     ********************************************************************************/
    int32_t read_from(
        char *b,
        int32_t size,
        address *from);

    /*********************************************************************************
     * Send to
     * Return sent size.
     ********************************************************************************/
    int32_t send(
        const char *b,
        int32_t size,
        const address &to);
};
DEFINE_SMART_POINTERS(flow_udp);

}  // namespace flow
}  // namespace transport
}  // namespace pump

#endif