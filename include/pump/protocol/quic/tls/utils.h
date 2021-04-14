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

#include "pump/ssl/hkdf.h"
#include "pump/protocol/quic/tls/types.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    /*********************************************************************************
     * Pack and unpack bytes.
     ********************************************************************************/
    uint8_t* pack_bytes(
        uint8_t *des, 
        uint8_t *end, 
        const std::string &src);

    uint8_t* pack_bytes(
        uint8_t *des, 
        uint8_t *end, 
        const uint8_t *src, 
        int32_t size);

    const uint8_t* unpack_bytes(
        const uint8_t *src, 
        const uint8_t *end, 
        uint8_t *des, 
        int32_t size);

    const uint8_t* unpack_bytes(
        const uint8_t *src, 
        const uint8_t *end, 
        std::string &des, 
        int32_t size);

    /*********************************************************************************
     * Pack and unpack uint8.
     ********************************************************************************/
    uint8_t* pack_uint8(
        uint8_t *p, 
        uint8_t *end, 
        uint8_t val);

    const uint8_t* unpack_uint8(
        const uint8_t *p, 
        const uint8_t *end, 
        uint8_t &val);

    /*********************************************************************************
     * Pack and unpack uint16.
     ********************************************************************************/
    uint8_t* pack_uint16(
        uint8_t *p, 
        uint8_t *end, 
        uint16_t val);

    const uint8_t* unpack_uint16(
        const uint8_t *p, 
        const uint8_t *end, 
        uint16_t &val);

    /*********************************************************************************
     * Pack and unpack uint24.
     ********************************************************************************/
    uint8_t* pack_uint24(
        uint8_t *p, 
        uint8_t *end, 
        uint32_t val);

    const uint8_t* unpack_uint24(
        const uint8_t *p, 
        const uint8_t *end, 
        uint32_t &val);

    /*********************************************************************************
     * Pack and unpack uint32.
     ********************************************************************************/
    uint8_t* pack_uint32(
        uint8_t *p, 
        uint8_t *end, 
        uint32_t val);
        
    const uint8_t* unpack_uint32(
        const uint8_t *p, 
        const uint8_t *end, 
        uint32_t &val);

    /*********************************************************************************
     * Check element array contains the element or not.
     ********************************************************************************/
    template <typename T>
    bool is_contains(const std::vector<T> &elems, T &elem) {
        for (auto &the_elem : elems) {
            if (elem == the_elem) {
                return true;
            }
        }
        return false;
    }

    /*********************************************************************************
     * New cipher suite context.
     ********************************************************************************/
    cipher_suite_context_ptr new_cipher_suite_context(cipher_suite_type suite_type);

    /*********************************************************************************
     * Delete cipher suite context.
     ********************************************************************************/
    void delete_cipher_suite_context(cipher_suite_context_ptr ctx);

    /*********************************************************************************
     * Cipher suite extract.
     ********************************************************************************/
    std::string cipher_suite_extract(
        cipher_suite_context_ptr ctx, 
        const std::string &salt, 
        const std::string &key);

    /*********************************************************************************
     * Cipher suite expand label.
     ********************************************************************************/
    std::string cipher_suite_expand_label(
        cipher_suite_context_ptr ctx,
        const std::string &key, 
        const std::string &context,
        const std::string &label,
        int32_t length);

    /*********************************************************************************
     * Cipher suite device secret.
     ********************************************************************************/
    std::string cipher_suite_device_secret(
        cipher_suite_context_ptr suite_param,
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
     * Transform tp hash algorithm.
     ********************************************************************************/
    ssl::hash_algorithm transform_to_hash_algo(ssl::signature_scheme scheme);

    /*********************************************************************************
     * Transform to signature algorithm.
     ********************************************************************************/
    ssl::signature_algorithm transform_to_sign_algo(ssl::signature_scheme scheme);

    /*********************************************************************************
     * Signature message.
     ********************************************************************************/
    std::string signature_message(
        ssl::hash_algorithm algo, 
        const std::string &context, 
        const std::string &msg);

}
}
}
}

#endif