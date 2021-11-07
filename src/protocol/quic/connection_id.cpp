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

#include "pump/debug.h"
#include "pump/codec/base64.h"
#include "pump/protocol/quic/connection_id.h"

namespace pump {
namespace protocol {
namespace quic {

    connection_id::connection_id()
      : len_(0) {
        memset(id_, 0, sizeof(id_));
    }

    connection_id::connection_id(const connection_id &id) {
        len_ = id.len_;
        memcpy(id_, id.id_, id.len_);
    }

    connection_id::connection_id(const block_t* id, int32_t len) {
        if (len < 0 || len > MAX_CONNECTION_ID_LEN) {
            PUMP_ABORT();
        }
        len_ = len;
        memcpy(id_, id, len);
    }

    std::string connection_id::to_string() const {
        std::string id(id_, len_);
        return codec::base64_encode(id);
    }


    connection_id& connection_id::operator=(const connection_id &id) {
        this->len_ = id.len_;
        memcpy(this->id_, id.id_, id.len_);
        return *this;
    }

    bool connection_id::operator==(const connection_id &id) const {
        if (this->len_ != id.len_) {
            return false;
        }
        if (this->len_ != 0 && memcmp(this->id_, id.id_, id.len_) != 0) {
            return false;
        }
        return true;
    }
}
}
}