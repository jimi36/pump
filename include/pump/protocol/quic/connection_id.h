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

#ifndef pump_protocol_quic_connection_id_h
#define pump_protocol_quic_connection_id_h

#include <string>

#include "pump/types.h"

namespace pump {
namespace protocol {
namespace quic {

    const int32_t MAX_CONNECTION_ID_LEN = 20;

    class connection_id {
      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        connection_id();
        connection_id(const connection_id &id);
        connection_id(const block_t *id, int32_t len);

        /*********************************************************************************
         * Format to base64 string
         ********************************************************************************/
        std::string to_string() const;

        /*********************************************************************************
         * Get connection id
         ********************************************************************************/
        PUMP_INLINE const block_t* id() const {
            return id_;
        }

        /*********************************************************************************
         * Get connection id length
         ********************************************************************************/
        PUMP_INLINE int32_t length() const {
            return len_;
        }

      public:
         /*********************************************************************************
         * Assignment operator
         ********************************************************************************/
        connection_id& operator=(const connection_id &id);

        /*********************************************************************************
         * Equal operator
         ********************************************************************************/
        bool operator==(const connection_id &id) const;

    private:
        block_t id_[MAX_CONNECTION_ID_LEN];
        int32_t len_;
    };

}
}
}

#endif
