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

#ifndef pump_proto_quic_cid_h
#define pump_proto_quic_cid_h

#include <string>

#include "pump/toolkit/buffer.h"

namespace pump {
namespace proto {
namespace quic {

    using toolkit::io_buffer;

    const int32_t MAX_CID_LENGTH = 20;

    class cid {
      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        cid();
        cid(const cid &id);
        cid(const std::string &id);
        cid(const block_t *id, int32_t len);

        /*********************************************************************************
         * Read from io buffer
         ********************************************************************************/
        bool read_from(io_buffer *iob, uint32_t len);

        /*********************************************************************************
         * Write to io buffer
         ********************************************************************************/
        bool write_to(io_buffer *iob) const;

        /*********************************************************************************
         * Format to base64 string
         ********************************************************************************/
        std::string to_string() const;

        /*********************************************************************************
         * Get connection id data
         ********************************************************************************/
        PUMP_INLINE const block_t* data() const {
            return id_.c_str();
        }

        /*********************************************************************************
         * Get connection id length
         ********************************************************************************/
        PUMP_INLINE int32_t length() const {
            return id_.size();
        }

      public:
         /*********************************************************************************
         * Assignment operator
         ********************************************************************************/
        cid& operator=(const cid &id);

        /*********************************************************************************
         * Equal operator
         ********************************************************************************/
        bool operator==(const cid &id) const;

    private:
        std::string id_;
    };

}
}
}

#endif
