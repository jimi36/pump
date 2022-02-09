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

#ifndef pump_proto_quic_flow_base_adjuster_h
#define pump_proto_quic_flow_base_adjuster_h

#include "pump/proto/quic/defines.h"
#include "pump/proto/quic/rtt_state.h"

namespace pump {
namespace proto {
namespace quic {
namespace flow {

class base_flow_adjuster {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    base_flow_adjuster(int64_t recv_window_size, int64_t recv_windown_max_size);

    /*********************************************************************************
     * Update send window offset
     ********************************************************************************/
    PUMP_INLINE void update_send_window_offset(int64_t offset) {
        if (offset > send_window_offset_) {
            send_window_offset_ += offset;
        }
    }

    /*********************************************************************************
     * Try to mark send blocked at new send window offset.
     * If no need block or blocked at current offset, return false.
     ********************************************************************************/
    PUMP_INLINE bool try_mark_send_block() {
        if (sent_bytes_ < send_window_offset_ ||
            send_window_offset_ == last_send_blocked_offset_) {
            return false;
        }
        last_send_blocked_offset_ = send_window_offset_;
        return true;
    }

  protected:
    /*********************************************************************************
     * Add sent bytes size
     ********************************************************************************/
    PUMP_INLINE void __add_sent_bytes(int64_t bytes) {
        sent_bytes_ += bytes;
    }

    /*********************************************************************************
     * Get send window size
     ********************************************************************************/
    PUMP_INLINE int64_t __get_send_window_size() {
        if (sent_bytes_ >= send_window_offset_) {
            return 0;
        }
        return send_window_offset_ - sent_bytes_;
    }

    /*********************************************************************************
     * Add read bytes size
     ********************************************************************************/
    PUMP_INLINE void __add_read_bytes(int64_t bytes) {
        if (read_bytes_ == 0) {
            __start_auto_tuning_epoch(time::get_clock_milliseconds());
        }
        read_bytes_ += bytes;
    }

    /*********************************************************************************
     * Update receive window offset
     * This will try to update receive window, and return updated receive window.
     * If no need to update receive window, just return zero.
     ********************************************************************************/
    PUMP_INLINE int64_t __update_recv_window_offset(const rtt_state *rs) {
        if (!__need_updata_recv_window()) {
            return 0;
        }

        __adjust_recv_window_size(rs);
        recv_window_offset_ = read_bytes_ + recv_window_size_;

        return recv_window_offset_;
    }

    /*********************************************************************************
     * Check whether receive windown needs to be updated
     ********************************************************************************/
    PUMP_INLINE bool __need_updata_recv_window() const {
        int64_t remaining = recv_window_offset_ - read_bytes_;
        return remaining <= recv_window_size_ * (1 - RECV_WINDOW_UPDATE_THRESHOLD);
    }

    /*********************************************************************************
     * Start auto tuning epoch
     ********************************************************************************/
    PUMP_INLINE void __start_auto_tuning_epoch(int64_t now) {
        epoch_start_time_ = now;
        epoch_start_offset_ = recv_window_offset_;
    }

    /*********************************************************************************
     * Adjust receive window size
     * For details about auto-tuning, see
     * https://docs.google.com/document/d/1SExkMmGiz8VYzV3s9E35JQlJ73vhzCekKkDi85F1qCE/edit?usp=sharing.
     ********************************************************************************/
    void __adjust_recv_window_size(const rtt_state *rs);

  protected:
    // For sending data
    int64_t sent_bytes_;
    int64_t send_window_offset_;
    int64_t last_send_blocked_offset_;

    // For receiving data
    int64_t read_bytes_;
    int64_t recv_highest_offset_;
    int64_t recv_window_offset_;
    int64_t recv_window_size_;
    int64_t recv_window_max_size_;

    // Tuning epoch
    int64_t epoch_start_time_;
    int64_t epoch_start_offset_;
};

}  // namespace flow
}  // namespace quic
}  // namespace proto
}  // namespace pump

#endif