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

#include "pump/utils.h"
#include "pump/debug.h"
#include "pump/ssl/cert.h"
#include "pump/protocol/quic/tls/utils.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    ssl::hash_context_ptr new_cipher_suite_hasher(cipher_suite_type cipher_suite) {
        switch (cipher_suite)
        {
        case TLS_AES_128_GCM_SHA256:
        case TLS_CHACHA20_POLY1305_SHA256:
            return ssl::create_hash_context(ssl::HASH_SHA256);
        case TLS_AES_256_GCM_SHA384:
            return ssl::create_hash_context(ssl::HASH_SHA384);
        }
        return nullptr;
    }

    bool load_tls13_cipher_suite_params(cipher_suite_type suite_type, 
                                        cipher_suite_params *suite) {
        switch (suite_type)
        {
        case TLS_AES_128_GCM_SHA256:
            suite->algo = ssl::HASH_SHA256;
            suite->type = suite_type;
            suite->key_len = 16;
            return true;
        case TLS_AES_256_GCM_SHA384:
            suite->algo = ssl::HASH_SHA384;
            suite->type = suite_type;
            suite->key_len = 32;
            return true;
        case TLS_CHACHA20_POLY1305_SHA256:
            suite->algo = ssl::HASH_SHA256;
            suite->type = suite_type;
            suite->key_len = 32;
            return true;
        }
        return false;
    }

    std::string cipher_suite_extract(cipher_suite_params *suite_params, 
                                     const std::string &salt, 
                                     const std::string &key) {
        return hkdf_extract(suite_params->algo, salt, key);
    }

    std::string cipher_suite_expand_label(cipher_suite_params *suite_params,
                                          const std::string &key, 
                                          const std::string &context,
                                          const std::string &label,
                                          int32_t result_length) {
        return hkdf_expand_label(suite_params->algo, 
                                 key, 
                                 context, 
                                 label, 
                                 result_length);
    }

    std::string cipher_suite_device_secret(cipher_suite_params *suite_params,
                                           const std::string &key,
                                           const std::string &label,
                                           ssl::hash_context_ptr transcript) {                    
        std::string context;
        if (!transcript) {
            transcript = ssl::create_hash_context(suite_params->algo);
            PUMP_DEBUG_CHECK(ssl::sum_hash(transcript, context));
            ssl::free_hash_context(transcript);
        } else {
            PUMP_DEBUG_CHECK(ssl::sum_hash(transcript, context));
        }
        return hkdf_expand_label(suite_params->algo, 
                                 key, 
                                 context, 
                                 label, 
                                 (int32_t)context.size());
    }

    std::string hkdf_extract(ssl::hash_algorithm algo, 
                             const std::string &salt, 
                             const std::string &key) {
        std::string out;
        if (key.empty()) {
            std::string new_key(ssl::hash_digest_length(algo), 0);
            PUMP_DEBUG_CHECK(ssl::hkdf_extract(algo, salt, new_key, out));
        } else {
            PUMP_DEBUG_CHECK(ssl::hkdf_extract(algo, salt, key, out));
        }
        return std::forward<std::string>(out);
    }

    std::string hkdf_expand_label(ssl::hash_algorithm algo, 
                                  const std::string &key, 
                                  const std::string &context,
                                  const std::string &label,
                                  int32_t result_length) {
        std::string info(10 + label.size() + context.size(), 0);
        uint8_t *p = (uint8_t*)info.data();
        *(uint16_t*)p = pump::change_endian((uint16_t)ssl::hash_digest_length(algo));
        p += 2;
        *(uint8_t*)p = uint8_t(6 + label.size());
        p += 1;
        memcpy(p, "tls13 ", 6);
        p += 6;
        memcpy(p, label.data(), label.size());
        p += label.size();
        *(uint8_t*)p = (uint8_t)context.size();
        p += 1;
        memcpy(p, context.data(), context.size());
        p += context.size();

        std::string out(result_length, 0);
        PUMP_DEBUG_CHECK(ssl::hkdf_expand(algo, key, info, out));
        return std::forward<std::string>(out);
    }

    bool certificate_load(std::vector<std::string> &certificates, 
                          std::vector<void_ptr> &certs) {
        bool ret = true;
        for (int32_t i = 0; i < (int32_t)certificates.size(); i++) {
            void_ptr cert = ssl::x509_certificate_new(
                                (void_ptr)certificates[i].data(), 
                                certificates[i].size());
            if (!cert) {
                ret = false;
                break;
            }
            certs.push_back(cert);
        }
        if (!ret) {
            for (int32_t i = 0; i < (int32_t)certs.size(); i++) {
                ssl::x509_certificate_delete(certs[i]);
            }
            certs.clear();
        }
        return ret;
    }

}
}
}
}