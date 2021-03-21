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

    /*********************************************************************************
     * TLS cipher suite parameters.
     ********************************************************************************/
    struct cipher_suite_params {
        ssl::hash_algorithm algorithm;
        cipher_suite_type type;
        int32_t key_len;
    };

    /*********************************************************************************
     * Filter tls version.
     ********************************************************************************/
    bool filter_tls_version(std::vector<version_type> &versions, 
                            version_type version);

    /*********************************************************************************
     * Filter alpn.
     ********************************************************************************/
    bool filter_application_protocol(std::vector<std::string> &alpns, 
                                     std::string &version);

    /*********************************************************************************
     * Filter tls13 cipher suite.
     ********************************************************************************/
    bool filter_tls13_cipher_suite(std::vector<cipher_suite_type> &cipher_suites, 
                                   cipher_suite_type cipher_suite);

    /*********************************************************************************
     * New cipher suite hasher.
     ********************************************************************************/
    ssl::hash_context_ptr new_cipher_suite_hasher(cipher_suite_type cipher_suite);

    /*********************************************************************************
     * Load tls13 cipher suite params.
     ********************************************************************************/
    bool load_tls13_cipher_suite_params(cipher_suite_type suite_type, 
                                        cipher_suite_params *suite_params);

    /*********************************************************************************
     * Cipher suite extract.
     ********************************************************************************/
    std::string cipher_suite_extract(cipher_suite_params *suite_params, 
                                     const std::string &salt, 
                                     const std::string &key);

    /*********************************************************************************
     * Cipher suite expand label.
     ********************************************************************************/
    std::string cipher_suite_expand_label(cipher_suite_params *suite_params,
                                          const std::string &key, 
                                          const std::string &context,
                                          const std::string &label);

    /*********************************************************************************
     * Cipher suite device secret.
     ********************************************************************************/
    std::string cipher_suite_device_secret(cipher_suite_params *suite_params,
                                           const std::string &key,
                                           const std::string &label,
                                           ssl::hash_context_ptr transcript);

    /*********************************************************************************
     * HKDF extract with hash algorithm.
     ********************************************************************************/
    std::string hkdf_extract(ssl::hash_algorithm algorithm, 
                             const std::string &salt, 
                             const std::string &key);

    /*********************************************************************************
     * HKDF expand label with hash algorithm.
     ********************************************************************************/
    std::string hkdf_expand_label(ssl::hash_algorithm algorithm, 
                                  const std::string &key,
                                  const std::string &context,
                                  const std::string &label,
                                  int32_t result_length);

    bool certificate_verify(std::vector<std::string> &certificates);

}
}
}
}

#endif