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
 
#ifndef pump_protocol_quic_tls_server_h
#define pump_protocol_quic_tls_server_h

#include "pump/fncb.h"
#include "pump/ssl/hash.h"
#include "pump/protocol/quic/tls/alert.h"
#include "pump/protocol/quic/tls/types.h"
#include "pump/protocol/quic/tls/message.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    class server_handshaker {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        server_handshaker();

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~server_handshaker();

        /*********************************************************************************
         * Start handshake
         * Client hello message will be sent to server.
         ********************************************************************************/
        bool handshake(config *cfg);

        /*********************************************************************************
         * Handshake
         ********************************************************************************/
        bool handshake(handshake_message *msg);

        /*********************************************************************************
         * Check handshake finished status
         ********************************************************************************/
        PUMP_INLINE bool is_handshaked() {
            return status_ == HANDSHAKE_SUCCESS;
        }

        /*********************************************************************************
         * Set send callback for debug
         ********************************************************************************/
        void set_send_callback(const pump_function<void (const std::string&)> cb) {
            send_callback_ = cb;
        }

      private:
        /*********************************************************************************
         * Handle client hello message
         ********************************************************************************/
        alert_code __handle_client_hello(handshake_message *msg);

        /*********************************************************************************
         * Send hello retry request message
         ********************************************************************************/
        alert_code __send_hello_retry_request(
            cipher_suite_type selected_cipher_suite,
            ssl::curve_type selected_curve);

        /*********************************************************************************
         * Send server hello message
         ********************************************************************************/
        bool __send_server_hello(
            cipher_suite_type selected_cipher_suite,
            ssl::curve_type selected_curve, 
            ssl::signature_scheme selected_scheme);

        /*********************************************************************************
         * Send encrypted extensions message
         ********************************************************************************/
        bool __send_encrypted_extensions();

        /*********************************************************************************
         * Send certificate request message
         ********************************************************************************/
        bool __send_certificate_request();

        /*********************************************************************************
         * Send certificate message
         ********************************************************************************/
        bool __send_certificate();

        /*********************************************************************************
         * Send certificate verify message
         ********************************************************************************/
        bool __send_certificate_verify();

        /*********************************************************************************
         * Send finished message
         ********************************************************************************/
        bool __send_finished();

        /*********************************************************************************
         * Write transcript
         ********************************************************************************/
        void __write_transcript(const std::string &data);

        /*********************************************************************************
         * Send data
         ********************************************************************************/
        void __send(const std::string &data) {
            if (send_callback_) {
              send_callback_(data);
            }
        }

      private:
        //  Handshake status
        handshake_status status_;

        // TLS config
        config cfg_;

        // Connection session
        connection_session session_;

        // Server hello message
        server_hello_message *hello_;

        // Client hello message
        client_hello_message client_hello_;

        // Handshake hash transcript
        ssl::hash_context_ptr transcript_;

        // For test
        pump_function<void (const std::string&)> send_callback_;
    };

}
}
}
}

#endif