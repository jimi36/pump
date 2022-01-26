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
#include "pump/proto/quic/cid.h"
#include "pump/proto/quic/utils.h"

namespace pump {
namespace proto {
namespace quic {

    cid::cid() {
    }

    cid::cid(const cid &id)
      : id_(id.id_) {
    }

    cid::cid(const block_t *id, int32_t len) {
        PUMP_ASSERT(id != nullptr && len > 0);
        id_.assign(id, len);
    }

    bool cid::read_from(io_buffer *iob, uint32_t len) {
        if (len == 0) {
            return false;
        } else {
            id_.resize(len);
            if (!iob->read((block_t*)id_.data(), id_.size())) {
                return false;
            }
        }
        return true;
    }

    bool cid::write_to(io_buffer *iob) const {
        if (id_.empty()) {
            return false;
        } else if (!iob->write(id_.data(), id_.size())) {
            return false;
        }
        return true;
    }

    std::string cid::to_string() const {
        return codec::base64_encode(id_);
    }


    cid& cid::operator=(const cid &id) {
        this->id_ = id.id_;
        return *this;
    }

    bool cid::operator==(const cid &id) const {
        if (this->id_ != id.id_) {
            return false;
        }
        return true;
    }
}
}
}