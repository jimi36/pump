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

#include "pump/time/timestamp.h"
#include "pump/proto/quic/flow/base_adjuster.h"

namespace pump {
namespace proto {
namespace quic {
namespace flow {

base_flow_adjuster::base_flow_adjuster(int64_t recv_window_size,
                                       int64_t recv_windown_max_size) :
    sent_bytes_(0),
    send_window_offset_(0),
    last_send_blocked_offset_(0),
    read_bytes_(0),
    recv_highest_offset_(0),
    recv_window_offset_(recv_window_size),
    recv_window_size_(recv_window_size),
    recv_window_max_size_(recv_windown_max_size),
    epoch_start_time_(0),
    epoch_start_offset_(0) {}

void base_flow_adjuster::__adjust_recv_window_size(const rtt_state *rs) {
    int64_t read_in_epoch = read_bytes_ - epoch_start_offset_;
    if (read_in_epoch <= recv_window_size_ / 2) {
        return;
    }

    int64_t rtt = rs->get_smoothed_rtt();
    if (rtt == 0) {
        return;
    }

    int64_t now = time::get_clock_milliseconds();
    float64_t fraction = float64_t(read_in_epoch) / float64_t(recv_window_size_);
    if (now - epoch_start_time_ <= 4 * (float64_t)rtt * fraction) {
        recv_window_size_ = recv_window_size_ * 2;
        if (recv_window_size_ > recv_window_max_size_) {
            recv_window_size_ = recv_window_max_size_;
        }
    }

    __start_auto_tuning_epoch(now);
}

}  // namespace flow
}  // namespace quic
}  // namespace proto
}  // namespace pump
