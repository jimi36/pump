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
 
#ifndef pump_protocol_quic_tls_utils_h
#define pump_protocol_quic_tls_utils_h

#include <vector>

#include "pump/protocol/quic/tls/types.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    bool filter_cipher_suite_tls13(
        std::vector<tls_cipher_suite_type> &cipher_suites, 
        tls_cipher_suite_type cipher_suite);

}
}
}
}

#endif