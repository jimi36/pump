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

#ifndef pump_proto_http_connection_h
#define pump_proto_http_connection_h

#include <pump/memory.h>
#include <pump/proto/http/frame.h>
#include <pump/proto/http/packet.h>
#include <pump/transport/tcp_transport.h>

namespace pump {
namespace proto {
namespace http {

using transport::base_transport_sptr;

const static int32_t state_none = 0x00;
const static int32_t state_started = 0x01;
const static int32_t state_upgraded = 0x02;
const static int32_t state_stopped = 0x04;
const static int32_t state_error = 0x05;

class connection;
DEFINE_SMART_POINTERS(connection);

struct http_callbacks {
    // Http packet callback
    pump_function<void(packet_sptr &)> packet_cb;
    // Http connection error callback
    pump_function<void(const std::string &)> error_cb;
};

struct websocket_callbacks {
    // Websocket frame callback
    pump_function<void(const char *, int32_t, bool)> frame_cb;
    // Websocket connection error callback
    pump_function<void(const std::string &)> error_cb;
};

class pump_lib connection : public std::enable_shared_from_this<connection> {
  public:
    friend class client;
    friend class server;

  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    connection(bool server, base_transport_sptr &transp);

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~connection();

    /*********************************************************************************
     * Start as http connection
     * This will async read one http packet.
     ********************************************************************************/
    bool start_http(service *sv, const http_callbacks &cbs);

    /*********************************************************************************
     * Send http packet
     ********************************************************************************/
    pump_inline bool send(packet_sptr &pk) {
        return send(pk.get());
    }
    pump_inline bool send(packet_sptr &&pk) {
        return send(pk.get());
    }
    bool send(packet *pk);

    /*********************************************************************************
     * Start websocket
     ********************************************************************************/
    bool start_websocket(const websocket_callbacks &cbs);

    /*********************************************************************************
     * Send websocket data
     ********************************************************************************/
    bool send(
        const char *b,
        int32_t size,
        bool text = true);

    /*********************************************************************************
     * Stop connection
     ********************************************************************************/
    void stop();

    /*********************************************************************************
     * Check connection upgraded status
     ********************************************************************************/
    pump_inline bool is_upgraded() const noexcept {
        return state_.load() == state_upgraded;
    }

    /*********************************************************************************
     * Check connection valid status
     ********************************************************************************/
    pump_inline bool is_valid() const noexcept {
        if (!transp_ || !transp_->is_started()) {
            return false;
        }
        return true;
    }

  protected:
    /*********************************************************************************
     * Read event callback
     ********************************************************************************/
    static void on_read(
        connection_wptr conn,
        const char *b,
        int32_t size);

    /*********************************************************************************
     * Disconnected event callback
     ********************************************************************************/
    static void on_disconnected(connection_wptr conn);

    /*********************************************************************************
     * Stopped event callback
     ********************************************************************************/
    static void on_stopped(connection_wptr conn);

  private:
    /*********************************************************************************
     * Read next one http packet.
     ********************************************************************************/
    bool __async_read_http_packet();

    /*********************************************************************************
     * Init websocket mask.
     ********************************************************************************/
    void __init_websocket_key();

    /*********************************************************************************
     * Send websocket ping frame
     ********************************************************************************/
    void __send_websocket_ping_frame();

    /*********************************************************************************
     * Send websocket pong frame
     ********************************************************************************/
    void __send_websocket_pong_frame();

    /*********************************************************************************
     * Send websocket close frame
     ********************************************************************************/
    void __send_wbesocket_close_frame();

    /*********************************************************************************
     * Handle http packet
     ********************************************************************************/
    int32_t __handle_http_packet(const char *b, int32_t size);

    /*********************************************************************************
     * Handle websocket frame
     ********************************************************************************/
    int32_t __handle_websocket_frame(const char *b, int32_t size);

    /*********************************************************************************
     * Async read
     ********************************************************************************/
    pump_inline bool __async_read() {
        if (!transp_) {
            return false;
        } else if (transp_->async_read() != transport::error_none) {
            return false;
        }
        return true;
    }

  private:
    // Status
    std::atomic_int32_t state_;

    // Read cache
    toolkit::io_buffer *cache_;

    // Pending http packet
    pump_function<packet *()> create_pending_packet_;
    packet_sptr pending_packet_;

    // Http callbacks
    http_callbacks http_cbs_;

    // Websocket frame
    frame_header ws_frame_;
    // Websocket mask key
    std::string ws_key_;

    // Websocket closed flag
    std::atomic_flag ws_closed_;
    // Websocket callbacks
    websocket_callbacks ws_cbs_;

    // Transport
    transport::base_transport_sptr transp_;
};
DEFINE_SMART_POINTERS(connection);

}  // namespace http
}  // namespace proto
}  // namespace pump

#endif
