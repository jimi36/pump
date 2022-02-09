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

#ifndef pump_proto_quic_flow_conn_adjuster_h
#define pump_proto_quic_flow_conn_adjuster_h

#include "pump/time/timestamp.h"
#include "pump/proto/quic/errors.h"
#include "pump/proto/quic/flow/base_adjuster.h"

namespace pump {
namespace proto {
namespace quic {
namespace flow {

class conn_flow_adjuster : public base_flow_adjuster {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    conn_flow_adjuster(int64_t recv_window_size, int64_t recv_windown_max_size) :
        base_flow_adjuster(recv_window_size, recv_windown_max_size) {}

    /*********************************************************************************
     * Add sent bytes size
     ********************************************************************************/
    PUMP_INLINE void add_sent_bytes(int64_t bytes) {
        __add_sent_bytes(bytes);
    }

    /*********************************************************************************
     * Get send window size
     ********************************************************************************/
    PUMP_INLINE int64_t get_send_window_size() {
        return __get_send_window_size();
    }

    /*********************************************************************************
     * Add read bytes size
     * If recevice window need to be updated, return true.
     ********************************************************************************/
    PUMP_INLINE bool add_read_bytes(int64_t bytes) {
        __add_read_bytes(bytes);
        if (!__need_updata_recv_window()) {
            return false;
        }
        return true;
    }

    /*********************************************************************************
     * Increment received highest offset
     ********************************************************************************/
    PUMP_INLINE error_code inc_recv_hishest_offset(int64_t inc) {
        recv_highest_offset_ += inc;
        if (recv_highest_offset_ > recv_window_offset_) {
            return EC_FLOW_CONTROL_ERROR;
        }
        return EC_NO_ERROR;
    }

    /*********************************************************************************
     * Get updated recevice window size
     ********************************************************************************/
    PUMP_INLINE int64_t get_updated_recv_window_size(const rtt_state *rs) {
        return __update_recv_window_offset(rs);
    }

    /*********************************************************************************
     * Adjust recevice window size
     ********************************************************************************/
    PUMP_INLINE void adjust_recv_window_size(int64_t stream_recv_windown_size) {
        if (stream_recv_windown_size > recv_window_size_) {
            if (stream_recv_windown_size > recv_window_max_size_) {
                recv_window_size_ = recv_window_max_size_;
            } else {
                recv_window_size_ = stream_recv_windown_size;
            }
            __start_auto_tuning_epoch(time::get_clock_milliseconds());
        }
    }

    /*********************************************************************************
     * The flow controller is reset when 0-RTT is rejected.
     * All stream data is invalidated, it's if we had never opened a stream and never
     * sent any data. At that point, we only have sent stream data, but we didn't have
     * the keys to open 1-RTT keys yet.
     ********************************************************************************/
    bool reset() {
        if (read_bytes_ > 0 || recv_highest_offset_ > 0 || epoch_start_time_ != 0) {
            return false;
        }

        sent_bytes_ = 0;
        last_send_blocked_offset_ = 0;

        return true;
    }

  private:
};
DEFINE_SMART_POINTER_TYPE(conn_flow_adjuster)

}  // namespace flow
}  // namespace quic
}  // namespace proto
}  // namespace pump

#endif