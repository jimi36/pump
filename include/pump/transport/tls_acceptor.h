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

#ifndef pump_transport_tls_acceptor_h
#define pump_transport_tls_acceptor_h

#include <unordered_map>

#include <pump/transport/tls_utils.h>
#include <pump/transport/base_acceptor.h>
#include <pump/transport/tls_handshaker.h>
#include <pump/transport/flow/flow_tls_acceptor.h>

namespace pump {
namespace transport {

class tls_acceptor;
DEFINE_SMART_POINTERS(tls_acceptor);

class pump_lib tls_acceptor
  : public base_acceptor,
    public std::enable_shared_from_this<tls_acceptor> {
  public:
    /*********************************************************************************
     * Create instance
     ********************************************************************************/
    pump_inline static tls_acceptor_sptr create(
        tls_credentials xcerd,
        const address &listen_address,
        uint64_t handshake_timeout_ns = 0) {
        pump_object_create_inline(
            tls_acceptor,
            obj,
            xcerd, listen_address, 
            handshake_timeout_ns);
        return tls_acceptor_sptr(obj, pump_object_destroy<tls_acceptor>);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~tls_acceptor();

    /*********************************************************************************
     * Start
     ********************************************************************************/
    virtual error_code start(
        service *sv,
        const acceptor_callbacks &cbs) override;

    /*********************************************************************************
     * Stop
     ********************************************************************************/
    virtual void stop() override;

  protected:
    /*********************************************************************************
     * Read event callback
     ********************************************************************************/
    virtual void on_read_event() override;

    /*********************************************************************************
     * TLS handshaked callback
     ********************************************************************************/
    static void on_handshaked(
        tls_acceptor_wptr acceptor,
        tls_handshaker *handshaker,
        bool success);

    /*********************************************************************************
     * Tls handskake stopped callback
     ********************************************************************************/
    static void on_handshake_stopped(
        tls_acceptor_wptr acceptor,
        tls_handshaker *handshaker);

  private:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    tls_acceptor(
        tls_credentials xcred,
        const address &listen_address,
        uint64_t handshake_timeout) noexcept;

    /*********************************************************************************
     * Open accept flow
     ********************************************************************************/
    virtual bool __open_accept_flow() override;

    /*********************************************************************************
     * Close accept flow
     ********************************************************************************/
    virtual void __close_accept_flow() override;

    /*********************************************************************************
     * Create handshaker
     ********************************************************************************/
    tls_handshaker *__create_handshaker();

    /*********************************************************************************
     * Remove handshaker
     ********************************************************************************/
    bool __remove_handshaker(tls_handshaker *handshaker);

    /*********************************************************************************
     * Stop all handshakers
     ********************************************************************************/
    void __stop_all_handshakers();

  private:
    // Credentials
    tls_credentials xcred_;

    // Handshake timeout
    uint64_t handshake_timeout_ns_;

    // Handshakers
    std::mutex handshaker_mx_;
    std::unordered_map<tls_handshaker *, tls_handshaker_sptr> handshakers_;

    // Acceptor flow
    flow::flow_tls_acceptor_sptr flow_;
};

}  // namespace transport
}  // namespace pump

#endif
