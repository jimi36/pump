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

#include "pump/debug.h"
#include "pump/config.h"
#include "pump/ssl/sign.h"

#if defined(PUMP_HAVE_OPENSSL)
extern "C" {
#include <openssl/bio.h> 
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
}
#endif

#if defined(PUMP_HAVE_GNUTLS)
extern "C" {
#include <gnutls/gnutls.h>
}
#endif

namespace pump {
namespace ssl {

    static int32_t __get_hash_id(hash_algorithm algo) {
        PUMP_ASSERT(algo > HASH_UNKNOWN && algo <= HASH_SHA512);
#if defined(PUMP_HAVE_OPENSSL)
        const static int32_t hash_ids[] = {
            -1, 
            NID_sha1,
            NID_sha224, 
            NID_sha256, 
            NID_sha384, 
            NID_sha512
        };
        return hash_ids[algo];
#else
        return -1;
#endif
    }

    bool verify_signature(
            signature_algorithm sign_algo, 
            hash_algorithm hash_algo,
            void_ptr cert, 
            const std::string &msg, 
            const std::string &sign) {
        bool ret = false;
#if defined(PUMP_HAVE_OPENSSL)
        switch (sign_algo) {
        case TLS_SIGNATURE_PKCS1V15:
        {
            EVP_PKEY *pubkey = X509_get_pubkey((X509*)cert);
            RSA *rsa = EVP_PKEY_get1_RSA(pubkey);
            ret = RSA_verify(
                    __get_hash_id(hash_algo), 
                    (const uint8_t*)msg.data(), 
                    (int32_t)msg.size(), 
                    (const uint8_t*)sign.data(), 
                    (int32_t)sign.size(), 
                    rsa) == 1;
            EVP_PKEY_free(pubkey);
            RSA_free(rsa);
            break;
        }
        case TLS_SIGNATURE_RSAPSS:
            break;
        case TLS_SIGNATURE_ECDSA:
        {
            EVP_PKEY *pubkey = X509_get_pubkey((X509*)cert);
            EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pubkey);
            ret = ECDSA_verify(
                    0, 
                    (const uint8_t*)msg.data(), 
                    (int32_t)msg.size(), 
                    (const uint8_t*)sign.data(), 
                    (int32_t)sign.size(), 
                    ec_key) == 1;
            EVP_PKEY_free(pubkey);
            EC_KEY_free(ec_key);
            break;
        }
        case TLS_SIGNATURE_ED25519:
            break;
        }
#endif
        return ret;
    }

}
}