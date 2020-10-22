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
            flow_udp() noexcept;

            /*********************************************************************************
             * Deconstructor
             ********************************************************************************/
            virtual ~flow_udp();

            /*********************************************************************************
             * Init flow
             * Return results:
             *     FLOW_ERR_NO    => success
             *     FLOW_ERR_ABORT => error
             ********************************************************************************/
            flow_error init(poll::channel_sptr &&ch, const address &bind_address);

#if defined(PUMP_HAVE_IOCP)
            /*********************************************************************************
             * Begin read task
             * If using IOCP this post an IOCP task for reading, else do nothing.
             * Return results:
             *     FLOW_ERR_NO    => success
             *     FLOW_ERR_ABORT => error
             ********************************************************************************/
            flow_error want_to_read();
#endif
            /*********************************************************************************
             * Read from
             ********************************************************************************/
#if defined(PUMP_HAVE_IOCP)
            c_block_ptr read_from(void_ptr iocp_task,
                                  int32_ptr size,
                                  address_ptr from_address);
#else
            c_block_ptr read_from(int32_ptr size, address_ptr from_address);
#endif
            /*********************************************************************************
             * Send to
             ********************************************************************************/
            int32 send(c_block_ptr b, uint32 size, const address &to_address);

          private:
            // Read cache
            toolkit::io_buffer_ptr read_iob_;
#if defined(PUMP_HAVE_IOCP)
            // Read task for IOCP
            void_ptr read_task_;
#endif
        };
        DEFINE_ALL_POINTER_TYPE(flow_udp);

    }  // namespace flow
}  // namespace transport
}  // namespace pump

#endif