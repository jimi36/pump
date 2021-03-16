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

#include "pump/protocol/quic/tls/utils.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    bool filter_cipher_suite_tls13(
        std::vector<tls_cipher_suite_type> &cipher_suites, 
        tls_cipher_suite_type cipher_suite) {
        for (int32_t i = 0; i < (int32_t)cipher_suites.size(); i++) {
            if (cipher_suite == cipher_suites[i]) {
                if (cipher_suite == TLS_AES_128_GCM_SHA256 ||
                    cipher_suite == TLS_AES_256_GCM_SHA384 ||
                    cipher_suite == TLS_CHACHA20_POLY1305_SHA256) {
                        return true;
                }
                return false;
            }
        }
        return false;
    }

}
}
}
}