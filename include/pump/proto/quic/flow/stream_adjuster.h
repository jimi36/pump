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

#ifndef pump_proto_quic_flow_stream_adjuster_h
#define pump_proto_quic_flow_stream_adjuster_h

#include "pump/proto/quic/flow/conn_adjuster.h"

namespace pump {
namespace proto {
namespace quic {
namespace flow {

class stream_flow_adjuster : public base_flow_adjuster {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    stream_flow_adjuster(int64_t recv_window_size,
                         int64_t recv_windown_max_size,
                         int64_t stream_id,
                         conn_flow_adjuster_sptr &cfa);

    /*********************************************************************************
     * Add sent bytes size
     ********************************************************************************/
    PUMP_INLINE void add_sent_bytes(int64_t bytes) {
        __add_sent_bytes(bytes);
        cfa_->add_sent_bytes(bytes);
    }

    /*********************************************************************************
     * Get send window size
     ********************************************************************************/
    PUMP_INLINE int64_t get_send_window_size() {
        int64_t ssize = __get_send_window_size();
        int64_t csize = cfa_->get_send_window_size();
        return ssize < csize ? ssize : csize;
    }

    /*********************************************************************************
     * Add read bytes size
     * If recevice window need to be updated, return true.
     ********************************************************************************/
    PUMP_INLINE bool add_read_bytes(int64_t bytes) {
        __add_read_bytes(bytes);
        if (recv_window_offset_ || !__need_updata_recv_window()) {
            return false;
        }
        return true;
    }

    /*********************************************************************************
     * Update received highest offset
     ********************************************************************************/
    error_code update_recv_highest_offset(int64_t offset, bool final);

    /*********************************************************************************
     * Get recevice window size
     ********************************************************************************/
    int64_t get_updated_recv_window_size(const rtt_state *rs);

    /*********************************************************************************
     * Abandon unread data
     ********************************************************************************/
    PUMP_INLINE void abandon() {
        int64_t unread = recv_highest_offset_ - read_bytes_;
        if (unread > 0) {
            cfa_->add_read_bytes(unread);
        }
    }

  private:
    // Stream id
    int64_t stream_id_;

    // Recevied final offset flag
    bool recviced_final_offset_;

    // Connection flow adjuster
    conn_flow_adjuster_sptr cfa_;
};

}  // namespace flow
}  // namespace quic
}  // namespace proto
}  // namespace pump

#endif