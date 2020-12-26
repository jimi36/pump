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

#ifndef pump_transport_channel_h
#define pump_transport_channel_h

#include "pump/service.h"
#include "pump/poll/channel.h"
#include "pump/toolkit/buffer.h"
#include "pump/transport/address.h"
#include "pump/transport/callbacks.h"

namespace pump {
namespace transport {

    namespace flow {
        class flow_base;
    }

    /*********************************************************************************
     * Transport type
     ********************************************************************************/
    enum transport_type {
        UDP_TRANSPORT = 0,
        TCP_ACCEPTOR,
        TCP_DIALER,
        TCP_TRANSPORT,
        TLS_ACCEPTOR,
        TLS_DIALER,
        TLS_HANDSHAKER,
        TLS_TRANSPORT
    };

    /*********************************************************************************
     * Transport state
     ********************************************************************************/
    enum transport_state {
        TRANSPORT_INITED = 0,
        TRANSPORT_STARTING,
        TRANSPORT_STARTED,
        TRANSPORT_STOPPING,
        TRANSPORT_STOPPED,
        TRANSPORT_DISCONNECTING,
        TRANSPORT_DISCONNECTED,
        TRANSPORT_TIMEOUTING,
        TRANSPORT_TIMEOUTED,
        TRANSPORT_HANDSHAKING,
        TRANSPORT_FINISHED,
        TRANSPORT_ERROR
    };

    /*********************************************************************************
     * Transport read state
     ********************************************************************************/
    enum transport_read_state {
        READ_NONE = 0,
        READ_INVALID,
        READ_ONCE,
        READ_LOOP,
        READ_PENDING
    };

    /*********************************************************************************
     * Transport error
     ********************************************************************************/
    enum transport_error {
        ERROR_OK = 0,
        ERROR_UNSTART,
        ERROR_INVALID,
        ERROR_DISABLE,
        ERROR_AGAIN,
        ERROR_FAULT
    };

    class LIB_PUMP base_channel
      : public service_getter,
        public poll::channel {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        base_channel(transport_type type, service_ptr sv, int32_t fd) noexcept
            : service_getter(sv),
              poll::channel(fd),
              type_(type),
              transport_state_(TRANSPORT_INITED) {
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~base_channel() = default;

        /*********************************************************************************
         * Get transport type
         ********************************************************************************/
        PUMP_INLINE transport_type get_type() const {
            return type_;
        }

        /*********************************************************************************
         * Get started status
         ********************************************************************************/
        PUMP_INLINE bool is_started() const {
            return __is_status(TRANSPORT_STARTED);
        }

      protected:
        /*********************************************************************************
         * Set channel status
         ********************************************************************************/
        PUMP_INLINE bool __set_status(uint32_t expected, uint32_t desired) {
            return transport_state_.compare_exchange_strong(expected, desired);
        }

        /*********************************************************************************
         * Check transport is in status
         ********************************************************************************/
        PUMP_INLINE bool __is_status(uint32_t status) const {
            return transport_state_.load(std::memory_order_acquire) == status;
        }

        /*********************************************************************************
         * Post channel event
         ********************************************************************************/
        PUMP_INLINE void __post_channel_event(poll::channel_sptr &&ch, int32_t event) {
            get_service()->post_channel_event(ch, event);
        }
        PUMP_INLINE void __post_channel_event(poll::channel_sptr &ch, int32_t event) {
            get_service()->post_channel_event(ch, event);
        }

      protected:
        // Transport type
        transport_type type_;
        // Transport state
        std::atomic_uint transport_state_;
    };

    class LIB_PUMP base_transport : public base_channel {
      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        base_transport(transport_type type, service_ptr sv, int32_t fd)
            : base_channel(type, sv, fd),
              read_state_(READ_NONE),
              pending_send_size_(0) {
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~base_transport() {
#if !defined(PUMP_HAVE_IOCP)
            __stop_read_tracker();
            __stop_send_tracker();
#endif
        }

        /*********************************************************************************
         * Start
         ********************************************************************************/
        virtual transport_error start(
            service_ptr sv,
            const transport_callbacks &cbs) = 0;

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        virtual void stop() = 0;

        /*********************************************************************************
         * Force stop
         ********************************************************************************/
        virtual void force_stop() = 0;

        /*********************************************************************************
         * Read for once
         ********************************************************************************/
        virtual transport_error read_for_once() {
            return ERROR_DISABLE;
        }

        /*********************************************************************************
         * Read for loop
         ********************************************************************************/
        virtual transport_error read_for_loop() {
            return ERROR_DISABLE;
        }

        /*********************************************************************************
         * Send
         ********************************************************************************/
        virtual transport_error send(const block_t *b, int32_t size) {
            return ERROR_DISABLE;
        }

        /*********************************************************************************
         * Send io buffer
         * The ownership of io buffer will be transferred.
         ********************************************************************************/
        virtual transport_error send(toolkit::io_buffer_ptr iob) {
            return ERROR_DISABLE;
        }

        /*********************************************************************************
         * Send
         ********************************************************************************/
        virtual transport_error send(const block_t *b,
                                     int32_t size,
                                     const address &address) {
            return ERROR_DISABLE;
        }

        /*********************************************************************************
         * Get pending send buffer size
         ********************************************************************************/
        int32_t get_pending_send_size() const {
            return pending_send_size_;
        }

        /*********************************************************************************
         * Get local address
         ********************************************************************************/
        const address &get_local_address() const {
            return local_address_;
        }

        /*********************************************************************************
         * Get remote address
         ********************************************************************************/
        const address &get_remote_address() const {
            return remote_address_;
        }

      protected:
        /*********************************************************************************
         * Channel event callback
         ********************************************************************************/
        virtual void on_channel_event(int32_t ev) override;

      protected:
        /*********************************************************************************
         * Close transport flow
         ********************************************************************************/
        virtual void __close_transport_flow() = 0;

        /*********************************************************************************
         * Chane read state
         ********************************************************************************/
        uint32_t __change_read_state(uint32_t state);

        /*********************************************************************************
         * Interrupt and trigger callbacks
         ********************************************************************************/
        void __interrupt_and_trigger_callbacks();

#if !defined(PUMP_HAVE_IOCP)
        /*********************************************************************************
         * Start all trackers
         ********************************************************************************/
        bool __start_read_tracker(poll::channel_sptr &&ch);
        bool __start_send_tracker(poll::channel_sptr &&ch);

        /*********************************************************************************
         * Stop tracker
         ********************************************************************************/
        void __stop_read_tracker();
        void __stop_send_tracker();
#endif
      protected:
        // Local address
        address local_address_;
        // Remote address
        address remote_address_;

#if !defined(PUMP_HAVE_IOCP)
        // Channel trackers
        poll::channel_tracker_sptr r_tracker_;
        poll::channel_tracker_sptr s_tracker_;
#endif
        // Transport read state
        std::atomic_uint read_state_;

        // Pending send buffer size
        std::atomic_int32_t pending_send_size_;

        // Transport callbacks
        transport_callbacks cbs_;
    };

}  // namespace transport
}  // namespace pump

#endif
