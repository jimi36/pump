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

#ifndef pump_protocol_http_connection_h
#define pump_protocol_http_connection_h

#include "pump/memory.h"
#include "pump/toolkit/buffer.h"
#include "pump/protocol/http/packet.h"
#include "pump/protocol/http/ws_frame.h"
#include "pump/transport/tcp_transport.h"

namespace pump {
namespace protocol {
namespace http {

    class connection;
    DEFINE_ALL_POINTER_TYPE(connection);

    struct http_callbacks {
        // Http packet callback
        pump_function<void(packet_sptr &pk)> packet_cb;
        // Http connection error callback
        pump_function<void(const std::string &)> error_cb;
    };

    struct websocket_callbacks {
        // Websocket frame callback
        pump_function<void(const block_t*, int32_t, bool)> frame_cb;
        // Websocket connection error callback
        pump_function<void(const std::string &)> error_cb;
    };
    
    class LIB_PUMP connection 
      : public std::enable_shared_from_this<connection> {
      public:
        friend class server;

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        connection(
            bool server, 
            transport::base_transport_sptr &transp) noexcept;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~connection();

        /*********************************************************************************
         * Start http connection
         ********************************************************************************/
        bool start_http(service *sv, const http_callbacks &cbs);

        /*********************************************************************************
         * Mark upgrading websocket status
         ********************************************************************************/
        bool upgrading();

        /*********************************************************************************
         * Start websocket
         ********************************************************************************/
        bool start_websocket(const websocket_callbacks &cbs);

        /*********************************************************************************
         * Stop connection
         ********************************************************************************/
        void stop();

        /*********************************************************************************
         * Read again
         ********************************************************************************/
        bool read_again();

        /*********************************************************************************
         * Send data
         ********************************************************************************/
        bool send(const block_t *b, int32_t size);

        /*********************************************************************************
         * Check connection upgraded status 
         ********************************************************************************/
        bool is_upgraded() const;

        /*********************************************************************************
         * Check connection valid status
         ********************************************************************************/
        PUMP_INLINE bool is_valid() const {
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
            connection_wptr wptr, 
            const block_t *b, 
            int32_t size);

        /*********************************************************************************
         * Disconnected event callback
         ********************************************************************************/
        static void on_disconnected(connection_wptr wptr);

        /*********************************************************************************
         * Stopped event callback
         ********************************************************************************/
        static void on_stopped(connection_wptr wptr);

      private:
        /*********************************************************************************
         * Handle http packet
         ********************************************************************************/
        int32_t __handle_http_packet(const block_t *b, int32_t size);

        /*********************************************************************************
         * Handle websocket frame
         ********************************************************************************/
        int32_t __handle_websocket_frame(const block_t *b, int32_t size);

      private:
        // Status
        std::atomic_int32_t status_;

        // Read cache
        toolkit::io_buffer *cache_;

        // Incoming http packet
        packet_sptr incoming_packet_;
        pump_function<packet*()> create_incoming_packet_;

        // Http callbacks
        http_callbacks http_cbs_;

        // Websocket frame mask
        bool ws_has_mask_;
        uint8_t mask_key_[4];

        // Websocket closed
        std::atomic_flag closed_;

        // Frame decode info
        int32_t decode_phase_;
        ws_frame_header decode_hdr_;

        // Websocket callbacks
        websocket_callbacks ws_cbs_;

        // Transport
        transport::base_transport_sptr transp_;
    };
    DEFINE_ALL_POINTER_TYPE(connection);

    /*********************************************************************************
     * Send http packet
     ********************************************************************************/
    bool send_http_packet(connection_sptr &conn, packet *pk);

    /*********************************************************************************
     * Send http simple response
     ********************************************************************************/
    bool send_http_simple_response(
        connection_sptr &conn,
        int32_t status_code,
        const std::string &payload);

}  // namespace http
}  // namespace protocol
}  // namespace pump

#endif
