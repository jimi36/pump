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
 
#ifndef pump_protocol_quic_tls_client_h
#define pump_protocol_quic_tls_client_h

#include "pump/fncb.h"
#include "pump/protocol/quic/tls/alert.h"
#include "pump/protocol/quic/tls/types.h"
#include "pump/protocol/quic/tls/messages.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    class client_handshaker {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        client_handshaker();

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~client_handshaker();

        /*********************************************************************************
         * Start handshake
         * Client hello message will be sent to server.
         ********************************************************************************/
        bool handshake(const config &cfg);

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
        void set_callbacks(
            const pump_function<void (const std::string&)> send_cb,
            const pump_function<void (const connection_session&)> finished_cb) {
            send_callback_ = send_cb;
            finished_callback_ = finished_cb;
        }

      private:
        /*********************************************************************************
         * Send client hello message
         ********************************************************************************/
        bool __send_client_hello();

        /*********************************************************************************
         * Handle server hello message
         ********************************************************************************/
        alert_code __handle_server_hello(handshake_message *msg);

        /*********************************************************************************
         * Send client hello retry message
         ********************************************************************************/
        alert_code __send_hello_retry(handshake_message *msg);

        /*********************************************************************************
         * Handle encrypted extensions message
         ********************************************************************************/
        alert_code __handle_encrypted_extensions(handshake_message *msg);

        /*********************************************************************************
         * Handle certificate request tls13 message
         ********************************************************************************/
        alert_code __handle_certificate_request_tls13(handshake_message *msg);

        /*********************************************************************************
         * Handle certificate tls13 message
         ********************************************************************************/
        alert_code __handle_certificate_tls13(handshake_message *msg);

        /*********************************************************************************
         * Handle certificate verify message
         ********************************************************************************/
        alert_code __handle_certificate_verify(handshake_message *msg);

        /*********************************************************************************
         * Handle finished message
         ********************************************************************************/
        alert_code __handle_finished(handshake_message *msg);

        /*********************************************************************************
         * Send certificate tls13 message
         ********************************************************************************/
        alert_code __send_certificate_tls13();

        /*********************************************************************************
         * Send certificate verify message
         ********************************************************************************/
        alert_code __send_certificate_verify();

        /*********************************************************************************
         * Send finished message
         ********************************************************************************/
        alert_code __send_finished();

        /*********************************************************************************
         * Reset transcript
         ********************************************************************************/
        std::string __reset_transcript();

        /*********************************************************************************
         * Write transcript
         ********************************************************************************/
        void __write_transcript(const std::string &data);

        /*********************************************************************************
         * Send handshake message
         ********************************************************************************/
        void __send_handshake_message(handshake_message *msg, bool transcript = true) {
            if (transcript) {
                __write_transcript(pack_handshake_message(msg));
            }
            if (send_callback_) {
                send_callback_(pack_handshake_message(msg));
            }
        }

      private:
        //  Handshake status
        handshake_status status_;

        // Client hello message
        handshake_message *hello_;

        // Certificate request message
        certificate_request_tls13_message *cert_request_;

        // Handshake transcript hash context
        ssl::hash_context_ptr transcript_;

        // Connection session
        connection_session session_;

        // Send callback
        pump_function<void (const std::string&)> send_callback_;

        // Finished callback
        pump_function<void (const connection_session&)> finished_callback_;
    };

}
}
}
}

#endif