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

#ifndef pump_transport_tcp_dialer_h
#define pump_transport_tcp_dialer_h

#include <future>

#include <pump/transport/base_dialer.h>
#include <pump/transport/flow/flow_tcp_dialer.h>

namespace pump {
namespace transport {

class tcp_dialer;
DEFINE_SMART_POINTERS(tcp_dialer);

class pump_lib tcp_dialer
  : public base_dialer,
    public std::enable_shared_from_this<tcp_dialer> {
  public:
    /*********************************************************************************
     * Create instance
     ********************************************************************************/
    pump_inline static tcp_dialer_sptr create(
        const address &local_address,
        const address &remote_address,
        uint64_t connect_timeout_ns = 0) {
        pump_object_create_inline(
            tcp_dialer, 
            obj,
            local_address, 
            remote_address, 
            connect_timeout_ns);
        return tcp_dialer_sptr(obj, pump_object_destroy<tcp_dialer>);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~tcp_dialer() = default;

    /*********************************************************************************
     * Start
     ********************************************************************************/
    virtual error_code start(
        service *sv,
        const dialer_callbacks &cbs) override;

    /*********************************************************************************
     * Stop
     ********************************************************************************/
    virtual void stop() override;

  protected:
    /*********************************************************************************
     * Send event callback
     ********************************************************************************/
    virtual void on_send_event() override;

    /*********************************************************************************
     * Timeout event callback
     ********************************************************************************/
    static void on_timeout(tcp_dialer_wptr wptr);

  protected:
    /*********************************************************************************
     * Open dial flow
     ********************************************************************************/
    virtual bool __open_dial_flow() override;

    /*********************************************************************************
     * Shutdown dial flow
     ********************************************************************************/
    virtual void __shutdown_dial_flow() override;

    /*********************************************************************************
     * Close dial flow
     ********************************************************************************/
    virtual void __close_dial_flow() override;

  private:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    tcp_dialer(
        const address &local_address,
        const address &remote_address,
        uint64_t timeout_ns) noexcept;

  private:
    // Dialer flow
    flow::flow_tcp_dialer_sptr flow_;
};

class sync_tcp_dialer;
DEFINE_SMART_POINTERS(sync_tcp_dialer);

class pump_lib sync_tcp_dialer
  : public std::enable_shared_from_this<sync_tcp_dialer> {
  public:
    /*********************************************************************************
     * Create instance
     ********************************************************************************/
    static sync_tcp_dialer_sptr create() {
        pump_object_create_inline(sync_tcp_dialer, obj);
        return sync_tcp_dialer_sptr(obj, pump_object_destroy<sync_tcp_dialer>);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~sync_tcp_dialer() = default;

    /*********************************************************************************
     * Dial by sync
     ********************************************************************************/
    base_transport_sptr dial(
        service *sv,
        const address &local_address,
        const address &remote_address,
        uint64_t timeout_ns = 0);

  protected:
    /*********************************************************************************
     * Dialed callback
     ********************************************************************************/
    static void on_dialed(
        sync_tcp_dialer_wptr dialer,
        base_transport_sptr &transp,
        bool success);

    /*********************************************************************************
     * Dialed timeout callback
     ********************************************************************************/
    static void on_timeouted(sync_tcp_dialer_wptr dialer);

    /*********************************************************************************
     * Stopped dialing callback
     ********************************************************************************/
    static void on_stopped();

  private:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    sync_tcp_dialer() noexcept {
    }

  private:
    // Tcp dialer
    tcp_dialer_sptr dialer_;
    // Dial promise
    std::promise<base_transport_sptr> dial_promise_;
};

}  // namespace transport
}  // namespace pump

#endif
