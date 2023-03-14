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

#include <pump/transport/flow/flow_tls.h>
#include <pump/transport/base_transport.h>
#include <pump/toolkit/freelock_m2m_queue.h>

namespace pump {
namespace transport {

class tls_transport;
DEFINE_SMART_POINTERS(tls_transport);

class pump_lib tls_transport : public base_transport {
  public:
    /*********************************************************************************
     * Create instance
     ********************************************************************************/
    pump_inline static tls_transport_sptr create() {
        pump_object_create_inline(tls_transport, obj);
        return tls_transport_sptr(obj, pump_object_destroy<tls_transport>);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~tls_transport();

    /*********************************************************************************
     * Init
     ********************************************************************************/
    void init(
        flow::flow_tls_sptr &&flow,
        const address &local_address,
        const address &remote_address);

    /*********************************************************************************
     * Start tls transport
     ********************************************************************************/
    virtual error_code start(
        service *sv,
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
     * Async read for read once mode
     * For read loop mode, this will loop reading.
     * For read once mode, this will read only once.
     ********************************************************************************/
    virtual error_code async_read() override;

    /*********************************************************************************
     * Send
     ********************************************************************************/
    virtual error_code send(const char *b, int32_t size) override;

    /*********************************************************************************
     * Send io buffer
     * The ownership of io buffer will be transferred.
     ********************************************************************************/
    virtual error_code send(toolkit::io_buffer *iob) override;

  protected:
    /*********************************************************************************
     * Channel event callback
     ********************************************************************************/
    virtual void on_channel_event(int32_t ev, void *arg) override;

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
     * Handle sent buffer
     ********************************************************************************/
    void __handle_sent_buffer();

    /*********************************************************************************
     * Clear send pockets
     ********************************************************************************/
    void __clear_send_pockets();

  private:
    // TLS flow
    flow::flow_tls_sptr flow_;

    // Last send buffer
    volatile int32_t last_send_iob_size_;
    toolkit::io_buffer *last_send_iob_;

    // Pending send count
    std::atomic_int32_t pending_opt_cnt_;

    // Send buffer list
    toolkit::freelock_m2m_queue<toolkit::io_buffer *, 8> sendlist_;
};

}  // namespace transport
}  // namespace pump

#endif
