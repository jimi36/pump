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

#ifndef pump_transport_tcp_transport_h
#define pump_transport_tcp_transport_h

#include "pump/transport/flow/flow_tcp.h"
#include "pump/transport/base_transport.h"
#include "pump/toolkit/multi_freelock_queue.h"

namespace pump {
namespace transport {

    class tcp_transport;
    DEFINE_ALL_POINTER_TYPE(tcp_transport);

    class LIB_PUMP tcp_transport
      : public base_transport {

      public:
        /*********************************************************************************
         * Create instance
         ********************************************************************************/
        PUMP_INLINE static tcp_transport_sptr create() {
            INLINE_OBJECT_CREATE(obj, tcp_transport, ());
            return tcp_transport_sptr(obj, object_delete<tcp_transport>);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~tcp_transport();

        /*********************************************************************************
         * Init
         ********************************************************************************/
        void init(int32_t fd, const address &local_address, const address &remote_address);

        /*********************************************************************************
         * Start
         ********************************************************************************/
        virtual int32_t start(service_ptr sv, const transport_callbacks &cbs) override;

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        virtual void stop() override;

        /*********************************************************************************
         * Force stop
         ********************************************************************************/
        virtual void force_stop() override;

        /*********************************************************************************
         * Read for once
         ********************************************************************************/
        virtual int32_t read_for_once();

        /*********************************************************************************
         * Read for loop
         ********************************************************************************/
        virtual int32_t read_for_loop();

        /*********************************************************************************
         * Send
         ********************************************************************************/
        virtual int32_t send(const block_t *b, int32_t size) override;

        /*********************************************************************************
         * Send io buffer
         ********************************************************************************/
        virtual int32_t send(toolkit::io_buffer_ptr iob) override;

      protected:
        /*********************************************************************************
         * Read event callback
         ********************************************************************************/
#if defined(PUMP_HAVE_IOCP)
        virtual void on_read_event(net::iocp_task_ptr iocp_task) override;
#else
        virtual void on_read_event() override;
#endif
        /*********************************************************************************
         * Send event callback
         ********************************************************************************/
#if defined(PUMP_HAVE_IOCP)
        virtual void on_send_event(net::iocp_task_ptr iocp_task) override;
#else
        virtual void on_send_event() override;
#endif
      private:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        tcp_transport() noexcept;

        /*********************************************************************************
         * Open transport flow
         ********************************************************************************/
        bool __open_transport_flow();

        /*********************************************************************************
         * Shutdown transport flow
         ********************************************************************************/
        PUMP_INLINE void __shutdown_transport_flow() {
            if (flow_) {
                flow_->shutdown();
            }
        }

        /*********************************************************************************
         * Close transport flow
         ********************************************************************************/
        virtual void __close_transport_flow() override {
            if (flow_) {
                flow_->close();
            }
        }

        /*********************************************************************************
         * Async read
         ********************************************************************************/
        int32_t __async_read(int32_t state);

        /*********************************************************************************
         * Async send
         ********************************************************************************/
        bool __async_send(toolkit::io_buffer_ptr b);

        /*********************************************************************************
         * Send once
         ********************************************************************************/
        int32_t __send_once();

        /*********************************************************************************
         * Try doing dissconnected process
         ********************************************************************************/
        void __try_doing_disconnected_process();

        /*********************************************************************************
         * Clear sendlist
         ********************************************************************************/
        void __clear_sendlist();

        /*********************************************************************************
         * Reset last sent io buffer
         ********************************************************************************/
        PUMP_INLINE void __reset_last_sent_iobuffer() {
            last_send_iob_->sub_ref();
            last_send_iob_ = nullptr;
        }

      private:
        // Transport flow
        flow::flow_tcp_sptr flow_;

        // Last send buffer
        volatile int32_t last_send_iob_size_;
        volatile toolkit::io_buffer_ptr last_send_iob_;

        // Pending send count
        std::atomic_int32_t pending_send_cnt_;

        // Send buffer list
        toolkit::multi_freelock_queue<toolkit::io_buffer_ptr, 8> sendlist_;
    };

}  // namespace transport
}  // namespace pump

#endif
