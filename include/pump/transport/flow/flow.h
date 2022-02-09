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
#include "pump/transport/types.h"
#include "pump/transport/address.h"

namespace pump {
namespace transport {
namespace flow {

#define MAX_TCP_BUFFER_SIZE 4096  // 4KB
#define MAX_UDP_BUFFER_SIZE 8192  // 8KB

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
    pump_socket unbind();

    /*********************************************************************************
     * Shutdown
     ********************************************************************************/
    void shutdown(int32_t how);

    /*********************************************************************************
     * Close
     ********************************************************************************/
    void close();

    /*********************************************************************************
     * Get fd
     ********************************************************************************/
    PUMP_INLINE pump_socket get_fd() const {
        return fd_;
    }

    /*********************************************************************************
     * Check flow valid status
     ********************************************************************************/
    PUMP_INLINE bool is_valid() const {
        return fd_ > 0;
    }

  protected:
    // FD
    pump_socket fd_;
    // Channel
    poll::channel_wptr ch_;
};

}  // namespace flow
}  // namespace transport
}  // namespace pump

#endif