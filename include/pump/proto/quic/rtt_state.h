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

#ifndef pump_proto_quic_rtt_state_h
#define pump_proto_quic_rtt_state_h

#include "pump/types.h"

namespace pump {
namespace proto {
namespace quic {

class rtt_state {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    rtt_state();

    /*********************************************************************************
     * Set initial rtt
     ********************************************************************************/
    bool set_initial_rtt(int64_t r);

    /*********************************************************************************
     * Update with sample
     ********************************************************************************/
    void update(int64_t sample, int64_t ack_delay, int64_t now);

    /*********************************************************************************
     * Get packet timeout
     ********************************************************************************/
    int64_t get_pto(bool include_max_ack_delay);

    /*********************************************************************************
     * Reset
     ********************************************************************************/
    void reset();

    /*********************************************************************************
     * Set max ack delay
     ********************************************************************************/
    PUMP_INLINE void set_max_ack_delay(int64_t ack_delay) {
        max_ack_delay_ = ack_delay;
    }

    /*********************************************************************************
     * Get max ack delay
     ********************************************************************************/
    PUMP_INLINE int64_t get_max_ack_delay() const {
        return max_ack_delay_;
    }

    /*********************************************************************************
     * Get min rtt
     ********************************************************************************/
    PUMP_INLINE int64_t get_min_rtt() const {
        return min_;
    }

    /*********************************************************************************
     * Get latest rtt
     ********************************************************************************/
    PUMP_INLINE int64_t get_latest_rtt() const {
        return latest_;
    }

    /*********************************************************************************
     * Get smoothed rtt
     ********************************************************************************/
    PUMP_INLINE int64_t get_smoothed_rtt() const {
        return smoothed_;
    }

  private:
    // RTT inited flag
    bool inited_;

    // Min rtt
    int64_t min_;
    // Latest rtt
    int64_t latest_;
    // Smoothed rtt
    int64_t smoothed_;
    // Mean deviation
    int64_t mean_deviation_;

    // Max ack delay
    int64_t max_ack_delay_;
};

}  // namespace quic
}  // namespace proto
}  // namespace pump

#endif
