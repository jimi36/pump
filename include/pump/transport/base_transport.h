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

#include <pump/service.h>
#include <pump/poll/channel.h>
#include <pump/toolkit/buffer.h>
#include <pump/transport/types.h>
#include <pump/transport/address.h>
#include <pump/transport/callbacks.h>

namespace pump {
namespace transport {

namespace flow {
class flow_base;
}

const static int32_t max_tcp_buffer_size = 4096;  // 4KB
const static int32_t max_udp_buffer_size = 8192;  // 8KB

class pump_lib base_channel
  : public service_getter,
    public poll::channel {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    base_channel(
        transport_type type,
        service *sv,
        int32_t fd) noexcept
      : service_getter(sv),
        poll::channel(fd),
        type_(type),
        state_(state_none) {
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~base_channel() = default;

    /*********************************************************************************
     * Get transport type
     ********************************************************************************/
    pump_inline transport_type get_type() const noexcept {
        return type_;
    }

    /*********************************************************************************
     * Get started status
     ********************************************************************************/
    pump_inline bool is_started() const noexcept {
        return __is_state(state_started, std::memory_order_relaxed);
    }

  protected:
    /*********************************************************************************
     * Set channel state
     ********************************************************************************/
    pump_inline bool __set_state(
        transport_state expected,
        transport_state desired) noexcept {
        return state_.compare_exchange_strong(expected, desired);
    }

    /*********************************************************************************
     * Check transport state
     ********************************************************************************/
    pump_inline bool __is_state(transport_state state) const noexcept {
        return state_.load(std::memory_order_acquire) == state;
    }
    pump_inline bool __is_state(
        transport_state state,
        std::memory_order order) const noexcept {
        return state_.load(order) == state;
    }

    /*********************************************************************************
     * Post channel event
     ********************************************************************************/
    pump_inline bool __post_channel_event(
        poll::channel_sptr &&ch,
        int32_t event,
        void *arg = nullptr,
        poller_id pid = send_pid) {
        return get_service()->post_channel_event(ch, event, arg, pid);
    }

  protected:
    // Transport type
    transport_type type_;
    // Transport state
    std::atomic<transport_state> state_;
};

const static int32_t channel_event_disconnected = 0;
const static int32_t channel_event_buffer_sent = 1;
const static int32_t channel_event_read = 2;

class pump_lib base_transport
  : public base_channel,
    public std::enable_shared_from_this<base_transport> {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    base_transport(
        int32_t type,
        service *sv,
        int32_t fd) noexcept
      : base_channel(type, sv, fd),
        rmode_(read_mode_none),
        rstate_(read_none),
        pending_send_size_(0) {
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~base_transport();

    /*********************************************************************************
     * Start
     ********************************************************************************/
    virtual error_code start(
        service *sv,
        read_mode mode,
        const transport_callbacks &cbs) {
        return error_fault;
    }

    /*********************************************************************************
     * Stop
     ********************************************************************************/
    virtual void stop() {
    }

    /*********************************************************************************
     * Force stop
     ********************************************************************************/
    virtual void force_stop() {
    }

    /*********************************************************************************
     * Async read for read once mode
     * For read loop mode, this will loop reading.
     * For read once mode, this will read only once.
     ********************************************************************************/
    virtual error_code async_read() {
        return error_fault;
    }

    /*********************************************************************************
     * Send buffer
     ********************************************************************************/
    virtual error_code send(const char *b, int32_t size) {
        return error_disable;
    }

    /*********************************************************************************
     * Send io buffer
     * The io buffer will be refer.
     ********************************************************************************/
    virtual error_code send(toolkit::io_buffer *iob) {
        return error_disable;
    }

    /*********************************************************************************
     * Send buffer to peer address
     ********************************************************************************/
    virtual error_code send(
        const char *b,
        int32_t size,
        const address &address) {
        return error_disable;
    }

    /*********************************************************************************
     * Send io buffer to peer address
     ********************************************************************************/
    virtual error_code send(
        toolkit::io_buffer *iob,
        const address &address) {
        return error_disable;
    }

    /*********************************************************************************
     * Get pending send buffer size
     ********************************************************************************/
    pump_inline int32_t get_pending_send_size() const noexcept {
        return pending_send_size_.load(std::memory_order_relaxed);
    }

    /*********************************************************************************
     * Get local address
     ********************************************************************************/
    pump_inline const address &get_local_address() const noexcept {
        return local_address_;
    }

    /*********************************************************************************
     * Get remote address
     ********************************************************************************/
    pump_inline const address &get_remote_address() const noexcept {
        return remote_address_;
    }

  protected:
    /*********************************************************************************
     * Channel event callback
     ********************************************************************************/
    virtual void on_channel_event(int32_t ev, void *arg) override;

  protected:
    /*********************************************************************************
     * Shutdown transport flow
     ********************************************************************************/
    virtual void __shutdown_transport_flow(int32_t how) {}

    /*********************************************************************************
     * Close transport flow
     ********************************************************************************/
    virtual void __close_transport_flow() {
    }

    /*********************************************************************************
     * Change read state
     ********************************************************************************/
    pump_inline bool __change_read_state(
        read_state from,
        read_state to) noexcept {
        return rstate_.compare_exchange_strong(from, to);
    }

    /*********************************************************************************
     * Try triggering dissconnected callback
     ********************************************************************************/
    bool __try_triggering_disconnected_callback();

    /*********************************************************************************
     * Trigger disconnected callbacks
     ********************************************************************************/
    bool __trigger_disconnected_callback();

    /*********************************************************************************
     * Trigger stopped callbacks
     ********************************************************************************/
    bool __trigger_stopped_callback();

    /*********************************************************************************
     * Install trackers
     ********************************************************************************/
    bool __install_read_tracker();
    bool __install_send_tracker();

    /*********************************************************************************
     * Uninstall tracker
     ********************************************************************************/
    void __uninstall_read_tracker();
    void __uninstall_send_tracker();

    /*********************************************************************************
     * Start trackers
     ********************************************************************************/
    bool __start_read_tracker();
    bool __start_send_tracker();

  protected:
    // Local address
    address local_address_;
    // Remote address
    address remote_address_;

    // Channel trackers
    poll::channel_tracker_sptr r_tracker_;
    poll::channel_tracker_sptr s_tracker_;

    // Transport read mode
    read_mode rmode_;
    std::atomic<read_state> rstate_;

    // Pending send buffer size
    std::atomic_int32_t pending_send_size_;

    // Transport callbacks
    transport_callbacks cbs_;
};

}  // namespace transport
}  // namespace pump

#endif
