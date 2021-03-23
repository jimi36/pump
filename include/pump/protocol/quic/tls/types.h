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

#include "pump/protocol/quic/tls/defines.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    /*********************************************************************************
     * TLS config.
     ********************************************************************************/
    struct config {
        std::string server_name;
        std::string alpn;
    };

    /*********************************************************************************
     * TLS cipher suite parameters.
     ********************************************************************************/
    struct cipher_suite_params {
        ssl::hash_algorithm algo;
        cipher_suite_type type;
        int32_t key_len;
    };

    /*********************************************************************************
     * TLS connection session.
     ********************************************************************************/
    struct connection_session {
        // Selected tls verson by handshake
        version_type version;

        ssl::key_pair keys;

        // Selected cipher cuite parameters by handshake
        cipher_suite_params suite_params;

        // Selected application protocol by handshake
        std::string alpn;

        bool enable_zero_rtt;

        std::vector<std::string> scts;

        std::string ocsp_staple;

        std::string master_secret;
        std::string client_secret;
        std::string server_secret;

        std::vector<void_ptr> certs;
    };

}
}
}
}

#endif