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

#include "pump/proto/quic/flow/stream_adjuster.h"

namespace pump {
namespace proto {
namespace quic {
namespace flow {

stream_flow_adjuster::stream_flow_adjuster(int64_t recv_window_size,
                                           int64_t recv_windown_max_size,
                                           int64_t stream_id,
                                           conn_flow_adjuster_sptr &cfa) :
    base_flow_adjuster(recv_window_size, recv_windown_max_size),
    stream_id_(stream_id),
    recviced_final_offset_(false),
    cfa_(cfa) {}

error_code stream_flow_adjuster::update_recv_highest_offset(int64_t offset, bool final) {
    if (offset == recv_highest_offset_) {
        if (final) {
            recviced_final_offset_ = true;
        }
        return EC_NO_ERROR;
    } else if (offset < recv_highest_offset_) {
        if (final) {
            return EC_FINAL_SIZE_ERROR;
        }
        return EC_NO_ERROR;
    }

    if (final) {
        recviced_final_offset_ = true;
    }

    if (offset > recv_window_offset_) {
        return EC_FLOW_CONTROL_ERROR;
    }
    int64_t inc = offset - recv_highest_offset_;
    recv_highest_offset_ = offset;

    return cfa_->inc_recv_hishest_offset(inc);
}

int64_t stream_flow_adjuster::get_updated_recv_window_size(const rtt_state *rs) {
    if (recviced_final_offset_) {
        return 0;
    }

    int64_t old_size = recv_window_size_;
    int64_t offset = __update_recv_window_offset(rs);
    if (recv_window_size_ > old_size) {
        cfa_->adjust_recv_window_size(recv_window_size_);
    }

    return offset;
}

}  // namespace flow
}  // namespace quic
}  // namespace proto
}  // namespace pump