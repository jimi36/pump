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

    bool load_tls13_cipher_suite_params(
        cipher_suite_type suite_type, 
        cipher_suite_parameter_ptr suite_param) {
        switch (suite_type)
        {
        case TLS_AES_128_GCM_SHA256:
            suite_param->algo = ssl::HASH_SHA256;
            suite_param->type = suite_type;
            suite_param->key_len = 16;
            return true;
        case TLS_AES_256_GCM_SHA384:
            suite_param->algo = ssl::HASH_SHA384;
            suite_param->type = suite_type;
            suite_param->key_len = 32;
            return true;
        case TLS_CHACHA20_POLY1305_SHA256:
            suite_param->algo = ssl::HASH_SHA256;
            suite_param->type = suite_type;
            suite_param->key_len = 32;
            return true;
        }
        return false;
    }

    std::string cipher_suite_extract(
        cipher_suite_parameter_ptr suite_param, 
        const std::string &salt, 
        const std::string &key) {
        return hkdf_extract(suite_param->algo, salt, key);
    }

    std::string cipher_suite_expand_label(
        cipher_suite_parameter_ptr suite_param,
        const std::string &key, 
        const std::string &context,
        const std::string &label,
        int32_t length) {
        return hkdf_expand_label(suite_param->algo, key, context, label, length);
    }

    std::string cipher_suite_device_secret(
        cipher_suite_parameter_ptr suite_param,
        const std::string &key,
        const std::string &label,
        ssl::hash_context_ptr transcript) {                    
        std::string context;
        if (!transcript) {
            transcript = ssl::create_hash_context(suite_param->algo);
            context = ssl::sum_hash(transcript);
            ssl::free_hash_context(transcript);
        } else {
            context = ssl::sum_hash(transcript);
        }
        return hkdf_expand_label(suite_param->algo, key, context, label, (int32_t)context.size());
    }

    std::string hkdf_extract(
        ssl::hash_algorithm algo, 
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

    std::string hkdf_expand_label(
        ssl::hash_algorithm algo, 
        const std::string &key, 
        const std::string &context,
        const std::string &label,
        int32_t length) {
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

        std::string out(length, 0);
        PUMP_DEBUG_CHECK(ssl::hkdf_expand(algo, key, info, out));
        return std::forward<std::string>(out);
    }

    bool certificate_load(
        std::vector<std::string> &certificates, 
        std::vector<ssl::x509_certificate_ptr> &certs) {
        bool ret = true;
        for (int32_t i = 0; i < (int32_t)certificates.size(); i++) {
            ssl::x509_certificate_ptr cert = ssl::load_x509_certificate_pem(certificates[i]);
            if (cert == nullptr) {
                ret = false;
                break;
            }
            certs.push_back(cert);
        }
        if (!ret) {
            for (int32_t i = 0; i < (int32_t)certs.size(); i++) {
                ssl::free_x509_certificate(certs[i]);
            }
            certs.clear();
        }
        return ret;
    }

    ssl::hash_algorithm transform_to_hash_algo(ssl::signature_scheme scheme) {
        switch (scheme) {
        case ssl::TLS_SIGN_SCHE_PKCS1WITHSHA1:
        case ssl::TLS_SIGN_SCHE_ECDSAWITHSHA1:
            return ssl::HASH_SHA1;
        case ssl::TLS_SIGN_SCHE_PKCS1WITHSHA256:
        case ssl::TLS_SIGN_SCHE_PSSWITHSHA256:
        case ssl::TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256:
            return ssl::HASH_SHA256;
        case ssl::TLS_SIGN_SCHE_PKCS1WITHSHA384:
        case ssl::TLS_SIGN_SCHE_PSSWITHSHA384:
        case ssl::TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384:
            return ssl::HASH_SHA384;
        case ssl::TLS_SIGN_SCHE_PKCS1WITHSHA512:
        case ssl::TLS_SIGN_SCHE_PSSWITHSHA512:
        case ssl::TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512:
            return ssl::HASH_SHA512;
        case ssl::TLS_SIGN_SCHE_ED25519:
        default:
            return ssl::HASH_UNKNOWN;
        }
    }

    ssl::signature_algorithm transform_to_sign_algo(ssl::signature_scheme scheme) {
        switch (scheme) {
        case ssl::TLS_SIGN_SCHE_PKCS1WITHSHA1:
        case ssl::TLS_SIGN_SCHE_PKCS1WITHSHA256:
        case ssl::TLS_SIGN_SCHE_PKCS1WITHSHA384:
        case ssl::TLS_SIGN_SCHE_PKCS1WITHSHA512:
            return ssl::TLS_SIGN_ALGO_PKCS1V15;
        case ssl::TLS_SIGN_SCHE_PSSWITHSHA256:
        case ssl::TLS_SIGN_SCHE_PSSWITHSHA384:
        case ssl::TLS_SIGN_SCHE_PSSWITHSHA512:
            return ssl::TLS_SIGN_ALGO_RSAPSS;
        case ssl::TLS_SIGN_SCHE_ECDSAWITHSHA1:
        case ssl::TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256:
        case ssl::TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384:
        case ssl::TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512:
            return ssl::TLS_SIGN_ALGO_ECDSA;
        case ssl::TLS_SIGN_SCHE_ED25519:
            return ssl::TLS_SIGN_ALGO_ED25519;
        default:
            return ssl::TLS_SIGN_ALGO_UNKNOWN;
        }
    }

    std::string sign_message(
        ssl::hash_algorithm algo,
        const std::string &context,
        const std::string &msg) {
        ssl::hash_context_ptr hash_ctx = ssl::create_hash_context(algo);
        PUMP_DEBUG_CHECK(ssl::update_hash(hash_ctx, signature_padding, (int32_t)sizeof(signature_padding)));
        PUMP_DEBUG_CHECK(ssl::update_hash(hash_ctx, context));
        PUMP_DEBUG_CHECK(ssl::update_hash(hash_ctx, msg));
        std::string sign = ssl::sum_hash(hash_ctx);
        ssl::free_hash_context(hash_ctx);
        return std::forward<std::string>(sign);
    }

}
}
}
}