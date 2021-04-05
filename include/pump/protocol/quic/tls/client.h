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

#include "pump/ssl/hash.h"
#include "pump/protocol/quic/tls/alert.h"
#include "pump/protocol/quic/tls/types.h"
#include "pump/protocol/quic/tls/message.h"

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

      private:
        /*********************************************************************************
         * Send client hello message
         ********************************************************************************/
        bool __send_client_hello(config *cfg);

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
        bool __send_certificate_tls13();

        /*********************************************************************************
         * Send finished message
         ********************************************************************************/
        bool __send_finished();

      private:
        //  Handshake status
        handshake_status status_;

        // Connection session
        connection_session session_;

        // Handshake hash transcript
        ssl::hash_context_ptr transcript_;

        // Client hello message
        handshake_message client_hello_;

        // Certificate request message
        certificate_request_tls13_message cert_request_;
    };

}
}
}
}

#endif