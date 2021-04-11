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
 
#ifndef pump_protocol_quic_tls_types_h
#define pump_protocol_quic_tls_types_h

#include <string>
#include <vector>

#include "pump/ssl/cert.h"
#include "pump/ssl/hash.h"
#include "pump/ssl/ecdhe.h"
#include "pump/protocol/quic/tls/defines.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    /*********************************************************************************
     * TLS config.
     ********************************************************************************/
    struct config {
        std::string cert_pem;
        std::string server_name;
        std::string alpn;
    };
    DEFINE_RAW_POINTER_TYPE(config)

    /*********************************************************************************
     * TLS cipher suite context.
     ********************************************************************************/
    struct cipher_suite_context {
        ssl::hash_algorithm algo;
        cipher_suite_type type;
        int32_t key_len;
    };
    DEFINE_RAW_POINTER_TYPE(cipher_suite_context)

    /*********************************************************************************
     * TLS connection session.
     ********************************************************************************/
    struct connection_session {
        // TLS verson
        version_type version;

        // TLS server name
        std::string server_name;

        // TLS signature scheme
        ssl::signature_scheme sign_scheme;

        // TLS ecdhe context
        ssl::ecdhe_context_ptr ecdhe_ctx;

        // TLS cipher suite context
        cipher_suite_context_ptr cipher_suite_ctx;

        // 0-RTT enable status
        bool enable_zero_rtt;

        // Application protocol
        std::string alpn;

        // TLS ocsp staple
        std::string ocsp_staple;

        // TLS signed certificate timestamp
        std::vector<std::string> scts;

        std::string master_secret;
        std::string client_secret;
        std::string server_secret;
        std::string traffic_secret;
        std::string handshake_secret;
        std::string export_master_secret;

        // Certificates
        std::vector<ssl::x509_certificate_ptr> certs;

        // Peer certificates
        std::vector<ssl::x509_certificate_ptr> peer_certs;
    };
    DEFINE_RAW_POINTER_TYPE(connection_session)

}
}
}
}

#endif