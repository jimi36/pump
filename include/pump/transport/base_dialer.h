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

#ifndef pump_transport_dialer_h
#define pump_transport_dialer_h

#include <pump/transport/base_transport.h>

namespace pump {
namespace transport {

class pump_lib base_dialer : public base_channel {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    base_dialer(
        int32_t type,
        const address &local_address,
        const address &remote_address,
        uint64_t connect_timeout_ns) noexcept
      : base_channel(type, nullptr, -1),
        local_address_(local_address),
        remote_address_(remote_address),
        connect_timeout_ns_(connect_timeout_ns) {
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~base_dialer();

    /*********************************************************************************
     * Start
     ********************************************************************************/
    virtual error_code start(
        service *sv,
        const dialer_callbacks &cbs) = 0;

    /*********************************************************************************
     * Stop
     ********************************************************************************/
    virtual void stop() = 0;

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
     * Open dial flow
     ********************************************************************************/
    virtual bool __open_dial_flow() {
        return false;
    }

    /*********************************************************************************
     * Shutdown dial flow
     ********************************************************************************/
    virtual void __shutdown_dial_flow() {
    }

    /*********************************************************************************
     * Close dial flow
     ********************************************************************************/
    virtual void __close_dial_flow() {
    }

  protected:
    /*********************************************************************************
     * Install dial tracker
     ********************************************************************************/
    bool __install_dial_tracker(poll::channel_sptr &&ch);

    /*********************************************************************************
     * Uninstall dial tracker
     ********************************************************************************/
    void __uninstall_dial_tracker();

    /*********************************************************************************
     * Start dial timer
     ********************************************************************************/
    bool __start_dial_timer(const time::timer_callback &cb);

    /*********************************************************************************
     * Stop connect timer
     ********************************************************************************/
    void __stop_dial_timer();

    /*********************************************************************************
     * Trigger interrupt callbacks
     ********************************************************************************/
    void __trigger_interrupt_callbacks();

  protected:
    // Local address
    address local_address_;
    // Remote address
    address remote_address_;

    // Connect timer
    uint64_t connect_timeout_ns_;
    std::shared_ptr<time::timer> connect_timer_;

    // Channel tracker
    poll::channel_tracker_sptr tracker_;

    // Dialer callbacks
    dialer_callbacks cbs_;
};
DEFINE_SMART_POINTERS(base_dialer);

}  // namespace transport
}  // namespace pump

#endif
