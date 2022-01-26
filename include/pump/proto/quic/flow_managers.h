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

#ifndef pump_proto_quic_flow_managers_h
#define pump_proto_quic_flow_managers_h

#include "pump/types.h"

namespace pump {
namespace proto {
namespace quic {

    class base_manager {
      public:
        base_manager();

      private:
        // For sending data
        int64_t sent_bytes_;
        int64_t send_window_pos_;
        int64_t last_blocked_pos_;

        // For receiving data
        int64_t read_bytes_;
        int64_t read_window_pos_;
    };

}
}
}

#endif