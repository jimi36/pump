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
 
#ifndef pump_protocol_quic_tls_client_handshake_h
#define pump_protocol_quic_tls_client_handshake_h

#include "pump/ssl/ssl_helper.h"
#include "pump/protocol/quic/tls/config.h"
#include "pump/protocol/quic/tls/handshake_message.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    class client_handshaker {
      public:
        client_handshaker();

        ~client_handshaker();

        bool handshake(config *cfg);

        bool handshake(handshake_message *msg);

        bool is_handshaked();

      private:

        bool __init_client_hello(config *cfg);

      private:
        client_hello_message hello_;
        ssl::ecdhe_key_pair ecdhe_keys_;
    };



}
}
}
}

#endif