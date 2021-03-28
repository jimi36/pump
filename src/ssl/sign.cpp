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

    int32_t get_signature_hash_algorithm(hash_algorithm hash_algo) {
#if defined(PUMP_HAVE_OPENSSL)
        switch (hash_algo)
        {
        case HASH_SHA1:
            return NID_sha1;
        case HASH_SHA224:
            return NID_sha224;
        case HASH_SHA256:
            return NID_sha256;
        case HASH_SHA384:
            return NID_sha384;
        case HASH_SHA512:
            return NID_sha512;
        default:
            return -1;
        }
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
            EVP_PKEY *pubkey = X509_get_pubkey((X509*)cert);
            RSA *rsa = EVP_PKEY_get1_RSA(pubkey);
            ret = RSA_verify(
                    get_signature_hash_algorithm(hash_algo), 
                    (const uint8_t*)msg.data(), 
                    (int32_t)msg.size(), 
                    (const uint8_t*)sign.data(), 
                    (int32_t)sign.size(), 
                    rsa);
            EVP_PKEY_free(pubkey);
            RSA_free(rsa);
            break;
        case TLS_SIGNATURE_RSAPSS:
        case TLS_SIGNATURE_ECDSA:
        case TLS_SIGNATURE_ED25519:
            break;
        }
#endif
        return ret;
    }

}
}