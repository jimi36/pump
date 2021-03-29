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
#include "pump/memory.h"
#include "pump/ssl/ecdhe.h"

#if defined(PUMP_HAVE_OPENSSL)
extern "C" {
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

    struct ecdhe_parameter {
        curve_type curve;
        std::string prikey;
        std::string pubkey;
    };

    static int32_t __get_curve_id(curve_type curve) {
        if (curve == TLS_CURVE_P256) {
            return NID_X9_62_prime256v1;
        } else if (curve == TLS_CURVE_P384) {
            return NID_secp384r1;
        } else if (curve == TLS_CURVE_P521) {
            return NID_secp521r1;
        }
        return -1;
    }

    static ecdhe_parameter_ptr create_x25519_parameter() {
#if defined(PUMP_HAVE_OPENSSL)
        bool ret = false;
        EVP_PKEY_CTX *pctx = nullptr;
        EVP_PKEY *pkey = nullptr;
        int32_t len = 0;
        char *pb = nullptr;
        BIO *bio = nullptr;
        ecdhe_parameter_ptr parameter = nullptr;

        if ((parameter = object_create<ecdhe_parameter>()) == nullptr) {
            return nullptr;
        }
        parameter->curve = TLS_CURVE_X25519;

        if ((pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL)) == NULL) {
            goto err;
        }

        if (EVP_PKEY_keygen_init(pctx) == 0) {
            goto err;
        }
        
        if (EVP_PKEY_keygen(pctx, &pkey) == 0) {
            goto err;
        }

        bio = BIO_new(BIO_s_mem());
        if (PEM_write_bio_PrivateKey(bio, pkey, NULL,NULL, 0, NULL, NULL) == 0) {
            goto err;
        }
        len = BIO_get_mem_data(bio, &pb);
        parameter->prikey.assign(pb, len);

        BIO_reset(bio);
        if (PEM_write_bio_PUBKEY(bio, pkey) == 0) {
            goto err;
        }
        len = BIO_get_mem_data(bio, &pb);
        parameter->pubkey.assign(pb, len);

        ret = true;

      err:
        if (pctx) {
            EVP_PKEY_CTX_free(pctx);
        }
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
        if (bio) {
            BIO_free(bio);
        }
        if (!ret && parameter) {
            object_delete(parameter);
            parameter = nullptr;
        }
        
        return parameter;
#else
        return nullptr;
#endif
    }

    static std::string gen_x25519_shared_key(ecdhe_parameter_ptr parameter, const std::string &pubkey) {
        std::string shared_key;
#if defined(PUMP_HAVE_OPENSSL)
        BIO *bio = nullptr;
        EVP_PKEY *pub_key = nullptr;
        EVP_PKEY *pri_key = nullptr;
        EVP_PKEY_CTX *pctx = nullptr;
        size_t shared_key_len = 0;

        // Load peer public key.
        bio = BIO_new_mem_buf(pubkey.data(), pubkey.size());
        if ((pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL)) == nullptr) {
            goto err;
        }

        // Load private key.
        BIO_reset(bio);
        BIO_set_mem_buf(bio, parameter->prikey.data(), parameter->prikey.size());
        if ((pri_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)) == nullptr) {
            goto err;
        }

        // Create context.
        if ((pctx = EVP_PKEY_CTX_new(pri_key, NULL)) == nullptr) {
            EVP_PKEY_free(pub_key);
            EVP_PKEY_free(pri_key);
            goto err;
        }
        
        if (EVP_PKEY_derive_init(pctx) <= 0 ||
            EVP_PKEY_derive_set_peer(pctx, pub_key) <= 0) {
            goto err;
        }

        if (EVP_PKEY_derive(pctx, NULL, &shared_key_len) <= 0) {
            goto err;
        }

        shared_key.resize(shared_key_len);
        if (EVP_PKEY_derive(pctx, (uint8_t*)shared_key.data(), &shared_key_len) <= 0) {
            goto err;
	    }

      err:
        if (bio) {
            BIO_free(bio);
        }
        if (pub_key) {
            EVP_PKEY_free(pub_key);
        }
        if (pri_key){
            EVP_PKEY_free(pri_key);
        }
        if (pctx) {
            EVP_PKEY_CTX_free(pctx);
        }
#endif
        return shared_key;
    }

    static ecdhe_parameter_ptr create_curve_parameter(curve_type curve) {
#if defined(PUMP_HAVE_OPENSSL)
        bool ret = false;
        EC_KEY *key = nullptr;
        const EC_GROUP *group = NULL;
        const EC_POINT *point = NULL;
        ecdhe_parameter_ptr parameter = nullptr;

        if ((parameter = object_create<ecdhe_parameter>()) == nullptr) {
            return nullptr;
        }
        parameter->curve = curve;

        if ((key = EC_KEY_new_by_curve_name(__get_curve_id(curve))) == nullptr) {
            goto err;
        }

        if (EC_KEY_generate_key(key) <= 0) {
            goto err;
        }

        if ((group = EC_KEY_get0_group(key)) == nullptr) {
            goto err;
        }

        if ((point = EC_KEY_get0_public_key(key)) == nullptr) {
            goto err;
        }

        parameter->pubkey.resize(64);
        if (EC_POINT_point2oct(group,
                               point,
                               POINT_CONVERSION_UNCOMPRESSED,
                               (uint8_t*)parameter->pubkey.data(),
                               64, 
                               NULL) != 64) {
            goto err;
        }

        parameter->prikey.resize(32);
        if (BN_bn2bin(EC_KEY_get0_private_key(key), (uint8_t*)parameter->prikey.data()) != 32) {
            goto err;
        }

        ret = true;

      err:
        if (key) {
            EC_KEY_free(key);
        }
        if (!ret && parameter) {
            object_delete(parameter);
            parameter = nullptr;
        }

        return parameter;
#else
        return nullptr;
#endif
    }

    static std::string gen_curve_shared_key(ecdhe_parameter_ptr parameter, const std::string &pubkey) {
        std::string shared_key;
#if defined(PUMP_HAVE_OPENSSL)
        EC_KEY *key = nullptr;
        const EC_GROUP *group = nullptr;
        BIGNUM *priv = nullptr;
        EC_POINT *p_ecdh1_public = nullptr;
        EC_POINT *p_ecdh2_public = nullptr;

        if ((key = EC_KEY_new_by_curve_name(__get_curve_id(parameter->curve))) == nullptr) {
            return shared_key;
        }

        if ((group = EC_KEY_get0_group(key)) == nullptr) {
            goto err;
        }

        /* 1==> Set ecdh1's public and privat key. */
        if ((p_ecdh1_public = EC_POINT_new(group)) == nullptr) {
            goto err;
        }

        if (EC_POINT_oct2point(group,
                               p_ecdh1_public,
                               (const uint8_t*)parameter->pubkey.data(),
                               parameter->pubkey.size(), nullptr) <= 0) {
            goto err;
        }

        if (EC_KEY_set_public_key(key, p_ecdh1_public) <= 0) {
            goto err;
        }

        priv = BN_bin2bn((const uint8_t*)parameter->prikey.data(),
                         parameter->prikey.size(),
                         nullptr);
        if (!EC_KEY_set_private_key(key, priv)) {
            goto err;
        }

        /* 2==> Set ecdh2's public key */
        if ((p_ecdh2_public = EC_POINT_new(group)) == nullptr) {
            goto err;
        }

        if (EC_POINT_oct2point(group,
                               p_ecdh2_public,
                               (const uint8_t*)pubkey.data(),
                               pubkey.size(),
                               nullptr) <= 0) {
            goto err;
        }

        if (EC_KEY_set_public_key(key, p_ecdh2_public) <= 0) {
            goto err;
        }

        /* 3==> Calculate the shared key of ecdh1 and ecdh2 */
        shared_key.resize(32);
        if (ECDH_compute_key((void_ptr)shared_key.data(),
                             shared_key.size(),
                             p_ecdh2_public,
                             key,
                             nullptr) != 32) {
            goto err;
        }

      err:
        if (priv) {
            BN_free(priv);
        }
        if (key) {
            EC_KEY_free(key);
        }
        if (p_ecdh1_public) {
            EC_POINT_free(p_ecdh1_public);
        }
        if (p_ecdh2_public) {
            EC_POINT_free(p_ecdh2_public);
        }
#endif
        return shared_key;
    }

    ecdhe_parameter_ptr create_ecdhe_parameter(curve_type curve) {
        if (curve == TLS_CURVE_X25519) {
            return create_x25519_parameter();
        } else {
            return create_curve_parameter(curve);
        }
    }

    void free_ecdhe_parameter(ecdhe_parameter_ptr parameter) {
        if (parameter) {
            object_delete(parameter);
        }
    }

    curve_type get_ecdhe_curve(ecdhe_parameter_ptr parameter) {
        if (parameter) {
            return parameter->curve;
        }
        return TLS_CURVE_UNKNOWN;
    }

    std::string get_ecdhe_prikey(ecdhe_parameter_ptr parameter) {
        if (parameter) {
            return parameter->prikey;
        }
        return "";
    }

    std::string get_ecdhe_pubkey(ecdhe_parameter_ptr parameter) {
        if (parameter) {
            return parameter->pubkey;
        }
        return "";
    }

    std::string gen_ecdhe_shared_key(ecdhe_parameter_ptr parameter, const std::string &pubkey) {
        if (parameter->curve == TLS_CURVE_X25519) {
            return gen_x25519_shared_key(parameter, pubkey);
        } else {
            return gen_curve_shared_key(parameter, pubkey);
        }
    }

}
}