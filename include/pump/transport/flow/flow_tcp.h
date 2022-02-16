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

#ifndef pump_transport_flow_tcp_h
#define pump_transport_flow_tcp_h

#include "pump/transport/flow/flow.h"

namespace pump {
namespace transport {
namespace flow {

class flow_tcp : public flow_base {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    flow_tcp() noexcept;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~flow_tcp();

    /*********************************************************************************
     * Init
     * Return results:
     *     ERROR_OK    => success
     *     ERROR_FAULT => error
     ********************************************************************************/
    error_code init(poll::channel_sptr &&ch, pump_socket fd);

    /*********************************************************************************
     * Read
     ********************************************************************************/
    pump_inline int32_t read(char *b, int32_t size) {
        return net::read(fd_, b, size);
    }

    /*********************************************************************************
     * Want to send
     * Try sending data as much as possible.
     * Return results:
     *      ERROR_OK    => send completely
     *      ERROR_AGAIN => try again
     *      ERROR_FAULT => error
     ********************************************************************************/
    error_code want_to_send(toolkit::io_buffer *iob);

    /*********************************************************************************
     * Send
     * Return results:
     *     ERROR_OK      => send completely
     *     ERROR_AGAIN   => try again
     *     ERROR_FAULT   => error
     ********************************************************************************/
    error_code send();

    /*********************************************************************************
     * Check there are data to send or not
     ********************************************************************************/
    pump_inline bool has_data_to_send() const {
        return (send_iob_ && send_iob_->size() > 0);
    }

  private:
    // Send buffer
    toolkit::io_buffer *send_iob_;
};
DEFINE_SMART_POINTER_TYPE(flow_tcp);

}  // namespace flow
}  // namespace transport
}  // namespace pump

#endif