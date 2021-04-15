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

#ifndef pump_transport_flow_tcp_acceptor_h
#define pump_transport_flow_tcp_acceptor_h

#include "pump/transport/flow/flow.h"

namespace pump {
namespace transport {
namespace flow {

    class flow_tcp_acceptor
      : public flow_base {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        flow_tcp_acceptor() noexcept;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~flow_tcp_acceptor();

        /*********************************************************************************
         * Init flow
         * Return results:
         *     FLOW_ERR_NO    => success
         *     FLOW_ERR_ABORT => error
         ********************************************************************************/
        int32_t init(
            poll::channel_sptr &&ch, 
            const address &listen_address);

        /*********************************************************************************
         * Accept
         ********************************************************************************/
        pump_socket accept(
            address_ptr local_address, 
            address_ptr remote_address);

      private:
        // IPV6
        bool is_ipv6_;

        // Accept buffer
        toolkit::io_buffer_ptr iob_;
    };
    DEFINE_ALL_POINTER_TYPE(flow_tcp_acceptor);

}  // namespace flow
}  // namespace transport
}  // namespace pump

#endif