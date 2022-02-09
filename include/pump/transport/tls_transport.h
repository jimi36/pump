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

#ifndef pump_transport_tls_transport_h
#define pump_transport_tls_transport_h

#include "pump/toolkit/fl_mc_queue.h"
#include "pump/transport/flow/flow_tls.h"
#include "pump/transport/base_transport.h"

namespace pump {
namespace transport {

class tls_transport;
DEFINE_SMART_POINTER_TYPE(tls_transport);

class LIB_PUMP tls_transport : public base_transport {
  public:
    /*********************************************************************************
     * Create instance
     ********************************************************************************/
    PUMP_INLINE static tls_transport_sptr create() {
        INLINE_OBJECT_CREATE(obj, tls_transport, ());
        return tls_transport_sptr(obj, object_delete<tls_transport>);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~tls_transport();

    /*********************************************************************************
     * Init
     ********************************************************************************/
    void init(flow::flow_tls_sptr &&flow,
              const address &local_address,
              const address &remote_address);

    /*********************************************************************************
     * Start tls transport
     ********************************************************************************/
    virtual error_code start(service *sv,
                             read_mode mode,
                             const transport_callbacks &cbs) override;

    /*********************************************************************************
     * Stop
     * Tls transport will delay stopping until all sendlist data is sent.
     ********************************************************************************/
    virtual void stop() override;

    /*********************************************************************************
     * Force stop
     ********************************************************************************/
    virtual void force_stop() override;

    /*********************************************************************************
     * Continue read for read once mode
     ********************************************************************************/
    virtual error_code continue_read() override;

    /*********************************************************************************
     * Send
     ********************************************************************************/
    virtual error_code send(const block_t *b, int32_t size) override;

    /*********************************************************************************
     * Send io buffer
     * The ownership of io buffer will be transferred.
     ********************************************************************************/
    virtual error_code send(toolkit::io_buffer *iob) override;

  protected:
    /*********************************************************************************
     * Channel event callback
     ********************************************************************************/
    virtual void on_channel_event(int32_t ev) override;

    /*********************************************************************************
     * Read event callback
     ********************************************************************************/
    virtual void on_read_event() override;

    /*********************************************************************************
     * Send event callback
     ********************************************************************************/
    virtual void on_send_event() override;

  private:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    tls_transport() noexcept;

    /*********************************************************************************
     * Shutdown transport flow
     ********************************************************************************/
    virtual void __shutdown_transport_flow(int32_t how) override;

    /*********************************************************************************
     * Close transport flow
     ********************************************************************************/
    virtual void __close_transport_flow() override;

    /*********************************************************************************
     * Async send
     ********************************************************************************/
    bool __async_send(toolkit::io_buffer *iob);

    /*********************************************************************************
     * Send once
     ********************************************************************************/
    error_code __send_once();

    /*********************************************************************************
     * Clear send pockets
     ********************************************************************************/
    void __clear_send_pockets();

    /*********************************************************************************
     * Reset last sent io buffer
     ********************************************************************************/
    PUMP_INLINE void __reset_last_sent_iobuffer() {
        last_send_iob_->unrefer();
        last_send_iob_ = nullptr;
    }

  private:
    // TLS flow
    flow::flow_tls_sptr flow_;

    // Last send buffer
    volatile int32_t last_send_iob_size_;
    toolkit::io_buffer *last_send_iob_;
    // volatile toolkit::io_buffer *last_send_iob_;

    // Pending send count
    std::atomic_int32_t pending_opt_cnt_;

    // Send buffer list
    toolkit::fl_mc_queue<toolkit::io_buffer *, 8> sendlist_;
};

}  // namespace transport
}  // namespace pump

#endif
