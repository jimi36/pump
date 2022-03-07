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

#ifndef pump_transport_flow_tcp_dialer_h
#define pump_transport_flow_tcp_dialer_h

#include "pump/transport/flow/flow.h"

namespace pump {
namespace transport {
namespace flow {

class flow_tcp_dialer : public flow_base {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    flow_tcp_dialer() noexcept;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~flow_tcp_dialer();

    /*********************************************************************************
     * Init
     * Return results:
     *     error_none    => success
     *     error_fault => error
     ********************************************************************************/
    error_code init(poll::channel_sptr &&ch, const address &bind_address);

    /*********************************************************************************
     * Post connect
     * Return results:
     *     error_none    => success
     *     error_fault => error
     ********************************************************************************/
    error_code post_connect(const address &remote_address);

    /*********************************************************************************
     * Connect
     * Return socket error code.
     ********************************************************************************/
    int32_t connect(address *local_address, address *remote_address);

  private:
    // IPV6
    bool is_ipv6_;
};
DEFINE_SMART_POINTERS(flow_tcp_dialer);

}  // namespace flow
}  // namespace transport
}  // namespace pump

#endif