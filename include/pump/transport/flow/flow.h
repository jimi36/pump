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

#ifndef pump_transport_flow_h
#define pump_transport_flow_h

#include "pump/debug.h"
#include "pump/net/iocp.h"
#include "pump/net/socket.h"
#include "pump/poll/channel.h"
#include "pump/toolkit/buffer.h"
#include "pump/transport/address.h"

namespace pump {
namespace transport {
    namespace flow {

#define MAX_FLOW_BUFFER_SIZE 4096

        enum flow_error {
            FLOW_ERR_NO = 0,
            FLOW_ERR_ABORT,
            FLOW_ERR_BUSY,
            FLOW_ERR_AGAIN,
            FLOW_ERR_NO_DATA,
            FLOW_ERR_COUNT
        };

        class flow_base : public toolkit::noncopyable {
          public:
            /*********************************************************************************
             * Constructor
             ********************************************************************************/
            flow_base() noexcept;

            /*********************************************************************************
             * Deconstructor
             ********************************************************************************/
            virtual ~flow_base() {
                close();
            }

            /*********************************************************************************
             * Unbind fd
             * This will return and unbind the fd from the flow.
             ********************************************************************************/
            int32 unbind();

            /*********************************************************************************
             * Shutdown
             ********************************************************************************/
            void shutdown();

            /*********************************************************************************
             * Close
             ********************************************************************************/
            void close();

            /*********************************************************************************
             * Get fd
             ********************************************************************************/
            PUMP_INLINE int32 get_fd() const {
                return fd_;
            }

            /*********************************************************************************
             * Check flow valid status
             ********************************************************************************/
            PUMP_INLINE bool is_valid() const {
                return fd_ > 0;
            }

          protected:
            // Channel fd
            int32 fd_;

            // Channel
            poll::channel_wptr ch_;

#if defined(PUMP_HAVE_IOCP)
            // IOCP extra function
            void_ptr extra_fns_;
#endif
        };
        DEFINE_ALL_POINTER_TYPE(flow_base);

    }  // namespace flow
}  // namespace transport
}  // namespace pump

#endif