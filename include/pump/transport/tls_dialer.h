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

#ifndef pump_transport_tls_dialer_h
#define pump_transport_tls_dialer_h

#include <future>

#include <pump/transport/base_dialer.h>
#include <pump/transport/tls_handshaker.h>
#include <pump/transport/flow/flow_tls_dialer.h>

namespace pump {
namespace transport {

class tls_dialer;
DEFINE_SMART_POINTERS(tls_dialer);

class pump_lib tls_dialer
  : public base_dialer,
    public std::enable_shared_from_this<tls_dialer> {
  public:
    /*********************************************************************************
     * Create instance
     ********************************************************************************/
    pump_inline static tls_dialer_sptr create(
        const address &local_address,
        const address &remote_address,
        uint64_t dial_timeout_ns = 0,
        uint64_t handshake_timeout_ns = 0) {
        pump_object_create_inline(
            obj,
            tls_dialer,
            (nullptr,
             local_address,
             remote_address,
             dial_timeout_ns,
             handshake_timeout_ns));
        return tls_dialer_sptr(obj, pump_object_destroy<tls_dialer>);
    }

    pump_inline static tls_dialer_sptr create_with_cred(
        tls_credentials xcred,
        const address &local_address,
        const address &remote_address,
        uint64_t dial_timeout_ns = 0,
        uint64_t handshake_timeout_ns = 0) {
        pump_object_create_inline(
            obj,
            tls_dialer,
            (xcred,
             local_address,
             remote_address,
             dial_timeout_ns,
             handshake_timeout_ns));
        return tls_dialer_sptr(obj, pump_object_destroy<tls_dialer>);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~tls_dialer();

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
    static void on_timeout(tls_dialer_wptr dialer);

    /*********************************************************************************
     * TLS handshake success callback
     ********************************************************************************/
    static void on_handshaked(
        tls_dialer_wptr dialer,
        tls_handshaker *handshaker,
        bool success);

    /*********************************************************************************
     * Tls handskake stopped callback
     ********************************************************************************/
    static void on_handshake_stopped(
        tls_dialer_wptr dialer,
        tls_handshaker *handshaker);

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
    tls_dialer(
        void *xcred,
        const address &local_address,
        const address &remote_address,
        uint64_t dial_timeout_ns,
        uint64_t handshake_timeout_ns);

  private:
    // Credentials
    tls_credentials xcred_;

    // Handshaker
    uint64_t handshake_timeout_ns_;
    tls_handshaker_sptr handshaker_;

    // Dialer flow
    flow::flow_tls_dialer_sptr flow_;
};

class tls_sync_dialer;
DEFINE_SMART_POINTERS(tls_sync_dialer);

class pump_lib tls_sync_dialer
  : public std::enable_shared_from_this<tls_sync_dialer> {
  public:
    /*********************************************************************************
     * Create instance
     ********************************************************************************/
    static tls_sync_dialer_sptr create() {
        pump_object_create_inline(obj, tls_sync_dialer, ());
        return tls_sync_dialer_sptr(obj, pump_object_destroy<tls_sync_dialer>);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~tls_sync_dialer() = default;

    /*********************************************************************************
     * Dial by synchronization
     ********************************************************************************/
    base_transport_sptr dial(
        service *sv,
        const address &local_address,
        const address &remote_address,
        uint64_t connect_timeout_ns,
        uint64_t handshake_timeout_ns);

  protected:
    /*********************************************************************************
     * Dialed callback
     ********************************************************************************/
    static void on_dialed(
        tls_sync_dialer_wptr dialer,
        base_transport_sptr &transp,
        bool success);

    /*********************************************************************************
     * Dial timeouted callback
     ********************************************************************************/
    static void on_timeouted(tls_sync_dialer_wptr dialer);

    /*********************************************************************************
     * Dial stopped callback
     ********************************************************************************/
    static void on_stopped();

  private:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    tls_sync_dialer() noexcept {}

  private:
    // Tcp dialer
    tls_dialer_sptr dialer_;
    // Dial promise
    std::promise<base_transport_sptr> dial_promise_;
};

}  // namespace transport
}  // namespace pump

#endif
