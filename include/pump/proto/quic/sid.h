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

#ifndef pump_proto_quic_sid_h
#define pump_proto_quic_sid_h

#include "pump/types.h"

namespace pump {
namespace proto {
namespace quic {

    typedef uint8_t stream_type;
    const stream_type bidi_stream  = 0x00;
    const stream_type unidi_stream = 0x02;

    typedef uint8_t stream_initiator_type;
    const stream_initiator_type client_initiator = 0x00;
    const stream_initiator_type server_initiator = 0x01;

    class sid {
      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        sid();
        sid(uint64_t id);
        sid(const sid &id);

        /*********************************************************************************
         * Set session id
         ********************************************************************************/
        PUMP_INLINE void set_id(uint64_t id) {
            id_ = id;
        }

        /*********************************************************************************
         * Get session id
         ********************************************************************************/
        PUMP_INLINE uint64_t get_id() const {
            return id_;
        }

        /*********************************************************************************
         * Get stream type
         ********************************************************************************/
        PUMP_INLINE stream_type get_stream_type() const {
            if ((stream_type(id_) & 0x02) == 0) {
                return bidi_stream;
            } else {
                return unidi_stream;
            }
        }

        /*********************************************************************************
         * Get stream initiator type
         ********************************************************************************/
        PUMP_INLINE stream_initiator_type get_stream_initiator_type() const {
            if ((stream_type(id_) & 0x01) == 0) {
                return client_initiator;
            } else {
                return server_initiator;
            }
        }

      private:
        uint64_t id_;
    };

}
}
}

#endif