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

#include "pump/ssl/sign.h"
#include "pump/ssl/hkdf.h"
#include "pump/ssl/ecdhe.h"
#include "pump/protocol/quic/tls/types.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    /*********************************************************************************
     * Check element array contains the element or not.
     ********************************************************************************/
    template <typename T>
    bool is_contains(std::vector<T> &elems, T &elem) {
        for (int32_t i = 0; i < (int32_t)elems.size(); i++) {
            if (elem == elems[i]) {
                return true;
            }
        }
        return false;
    }

    /*********************************************************************************
     * New cipher suite hasher.
     ********************************************************************************/
    ssl::hash_context_ptr new_cipher_suite_hasher(cipher_suite_type cipher_suite);

    /*********************************************************************************
     * Load tls13 cipher suite params.
     ********************************************************************************/
    bool load_tls13_cipher_suite_params(
        cipher_suite_type suite_type, 
        cipher_suite_parameter_ptr suite_param);

    /*********************************************************************************
     * Cipher suite extract.
     ********************************************************************************/
    std::string cipher_suite_extract(
        cipher_suite_parameter_ptr suite_param, 
        const std::string &salt, 
        const std::string &key);

    /*********************************************************************************
     * Cipher suite expand label.
     ********************************************************************************/
    std::string cipher_suite_expand_label(
        cipher_suite_parameter_ptr suite_param,
        const std::string &key, 
        const std::string &context,
        const std::string &label);

    /*********************************************************************************
     * Cipher suite device secret.
     ********************************************************************************/
    std::string cipher_suite_device_secret(
        cipher_suite_parameter_ptr suite_param,
        const std::string &key,
        const std::string &label,
        ssl::hash_context_ptr transcript);

    /*********************************************************************************
     * HKDF extract with hash algorithm.
     ********************************************************************************/
    std::string hkdf_extract(
        ssl::hash_algorithm algo, 
        const std::string &salt, 
        const std::string &key);

    /*********************************************************************************
     * HKDF expand label with hash algorithm.
     ********************************************************************************/
    std::string hkdf_expand_label(
        ssl::hash_algorithm algo, 
        const std::string &key,
        const std::string &context,
        const std::string &label,
        int32_t length);

    /*********************************************************************************
     * Certificate load.
     ********************************************************************************/
    bool certificate_load(
        std::vector<std::string> &certificates, 
        std::vector<ssl::x509_certificate_ptr> &certs);

    /*********************************************************************************
     * Certificate verify.
     ********************************************************************************/
    bool certificate_verify(std::vector<ssl::x509_certificate_ptr> &certs);

    /*********************************************************************************
     * Transform tp hash algorithm.
     ********************************************************************************/
    ssl::hash_algorithm transform_to_hash_algo(ssl::signature_scheme scheme);

    /*********************************************************************************
     * Transform to signature algorithm.
     ********************************************************************************/
    ssl::signature_algorithm transform_to_sign_algo(ssl::signature_scheme scheme);

    /*********************************************************************************
     * Sign message.
     ********************************************************************************/
    std::string sign_message(
        ssl::hash_algorithm algo, 
        const std::string &context, 
        const std::string &msg);

}
}
}
}

#endif