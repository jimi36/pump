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
}
#endif

#if defined(PUMP_HAVE_GNUTLS)
extern "C" {
#include <gnutls/gnutls.h>
}
#endif

namespace pump {
namespace ssl {

#if defined(PUMP_HAVE_OPENSSL)
static int32_t __to_ssl_curve_id(curve_group_type curve) {
    if (curve == TLS_CURVE_P256) {
        return NID_X9_62_prime256v1;
    } else if (curve == TLS_CURVE_P384) {
        return NID_secp384r1;
    } else if (curve == TLS_CURVE_P521) {
        return NID_secp521r1;
    }
    return -1;
}
#endif

static ecdhe_context *__new_X25519_context() {
    ecdhe_context *ctx = nullptr;
#if defined(PUMP_HAVE_OPENSSL)
    if ((ctx = object_create<ecdhe_context>()) == nullptr) {
        return nullptr;
    }
    ctx->group = TLS_CURVE_X25519;

    bool ret = false;
    BIO *bio = nullptr;
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *pctx = nullptr;

    do {
        int32_t len = 0;
        char *pb = nullptr;

        if ((pctx = EVP_PKEY_CTX_new_id(NID_X25519, nullptr)) == nullptr) {
            break;
        }
        if (EVP_PKEY_keygen_init(pctx) == 0 || EVP_PKEY_keygen(pctx, &pkey) == 0) {
            break;
        }

        if ((bio = BIO_new(BIO_s_mem())) == nullptr) {
            break;
        } else if (PEM_write_bio_PrivateKey(bio,
                                            pkey,
                                            nullptr,
                                            nullptr,
                                            0,
                                            nullptr,
                                            nullptr) == 0) {
            break;
        }
        len = BIO_get_mem_data(bio, &pb);
        ctx->prikey.assign(pb, len);

        BIO_free(bio);
        if ((bio = BIO_new(BIO_s_mem())) == nullptr) {
            break;
        } else if (PEM_write_bio_PUBKEY(bio, pkey) == 0) {
            break;
        }
        len = BIO_get_mem_data(bio, &pb);
        ctx->pubkey.assign(pb, len);

        ret = true;

    } while (false);

    if (bio) {
        BIO_free(bio);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (!ret) {
        object_delete(ctx);
        ctx = nullptr;
    }
#endif
    return ctx;
}

static bool __gen_X25519_shared_key(ecdhe_context *ctx,
                                    const std::string &pubkey,
                                    std::string &shared_key) {
    bool ret = false;
#if defined(PUMP_HAVE_OPENSSL)
    BIO *bio = nullptr;
    EVP_PKEY *pub_key = nullptr;
    EVP_PKEY *pri_key = nullptr;
    EVP_PKEY_CTX *pctx = nullptr;

    do {
        // Load peer public key.
        if ((bio = BIO_new_mem_buf(pubkey.data(), (int32_t)pubkey.size())) == nullptr) {
            break;
        }
        if ((pub_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr)) == nullptr) {
            break;
        }

        // Load private key.
        BIO_free(bio);
        if ((bio = BIO_new_mem_buf(ctx->prikey.data(), (int32_t)ctx->prikey.size())) ==
            nullptr) {
            break;
        }
        if ((pri_key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr)) ==
            nullptr) {
            break;
        }

        size_t shared_key_len = 0;
        if ((pctx = EVP_PKEY_CTX_new(pri_key, nullptr)) == nullptr) {
            break;
        }
        if (EVP_PKEY_derive_init(pctx) != 1 ||
            EVP_PKEY_derive_set_peer(pctx, pub_key) != 1 ||
            EVP_PKEY_derive(pctx, nullptr, &shared_key_len) != 1) {
            break;
        }

        shared_key.resize(shared_key_len);
        if (EVP_PKEY_derive(pctx, (uint8_t *)shared_key.data(), &shared_key_len) != 1) {
            break;
        }
        if (shared_key.size() != shared_key_len) {
            shared_key.resize(shared_key_len);
        }

        ret = true;

    } while (false);

    if (bio) {
        BIO_free(bio);
    }
    if (pub_key) {
        EVP_PKEY_free(pub_key);
    }
    if (pri_key) {
        EVP_PKEY_free(pri_key);
    }
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
#endif
    return ret;
}

static ecdhe_context *__new_curve_context(curve_group_type curve) {
    ecdhe_context *ctx = nullptr;
#if defined(PUMP_HAVE_OPENSSL)
    int32_t curve_id = __to_ssl_curve_id(curve);
    if (curve_id < 0) {
        return nullptr;
    }

    if ((ctx = object_create<ecdhe_context>()) == nullptr) {
        return nullptr;
    }
    ctx->group = curve;

    bool ret = false;
    EC_KEY *key = nullptr;

    do {
        const EC_GROUP *group = nullptr;
        const EC_POINT *point = nullptr;
        if ((key = EC_KEY_new_by_curve_name(curve_id)) == nullptr) {
            break;
        } else if (EC_KEY_generate_key(key) <= 0) {
            break;
        } else if ((group = EC_KEY_get0_group(key)) == nullptr) {
            break;
        } else if ((point = EC_KEY_get0_public_key(key)) == nullptr) {
            break;
        }

        ctx->pubkey.resize(64);
        if (EC_POINT_point2oct(group,
                               point,
                               POINT_CONVERSION_UNCOMPRESSED,
                               (uint8_t *)ctx->pubkey.data(),
                               64,
                               nullptr) != 64) {
            break;
        }

        ctx->prikey.resize(32);
        if (BN_bn2bin(EC_KEY_get0_private_key(key), (uint8_t *)ctx->prikey.data()) !=
            32) {
            break;
        }

        ret = true;

    } while (false);

    if (key) {
        EC_KEY_free(key);
    }
    if (!ret) {
        object_delete(ctx);
        ctx = nullptr;
    }
#endif
    return ctx;
}

static bool __gen_curve_shared_key(ecdhe_context *ctx,
                                   const std::string &pubkey,
                                   std::string &shared_key) {
    bool ret = false;
#if defined(PUMP_HAVE_OPENSSL)
    EC_KEY *key = nullptr;
    BIGNUM *priv = nullptr;
    EC_POINT *p_ecdh1_public = nullptr;
    EC_POINT *p_ecdh2_public = nullptr;

    do {
        const EC_GROUP *group = nullptr;
        if ((key = EC_KEY_new_by_curve_name(__to_ssl_curve_id(ctx->group))) == nullptr) {
            break;
        }
        if ((group = EC_KEY_get0_group(key)) == nullptr) {
            break;
        }

        /* 1==> Set ecdh1's public and privat key. */
        if ((p_ecdh1_public = EC_POINT_new(group)) == nullptr) {
            break;
        }
        if (EC_POINT_oct2point(group,
                               p_ecdh1_public,
                               (const uint8_t *)ctx->pubkey.data(),
                               ctx->pubkey.size(),
                               nullptr) <= 0) {
            break;
        }
        if (EC_KEY_set_public_key(key, p_ecdh1_public) <= 0) {
            break;
        }
        priv = BN_bin2bn((const uint8_t *)ctx->prikey.data(),
                         (int32_t)ctx->prikey.size(),
                         nullptr);
        if (priv == nullptr) {
            break;
        } else if (!EC_KEY_set_private_key(key, priv)) {
            break;
        }
        priv = nullptr;

        /* 2==> Set ecdh2's public key */
        if ((p_ecdh2_public = EC_POINT_new(group)) == nullptr) {
            break;
        }
        if (EC_POINT_oct2point(group,
                               p_ecdh2_public,
                               (const uint8_t *)pubkey.data(),
                               pubkey.size(),
                               nullptr) <= 0) {
            break;
        }
        if (EC_KEY_set_public_key(key, p_ecdh2_public) <= 0) {
            break;
        }

        /* 3==> Calculate the shared key of ecdh1 and ecdh2 */
        shared_key.resize(32);
        if (ECDH_compute_key((void *)shared_key.data(),
                             shared_key.size(),
                             p_ecdh2_public,
                             key,
                             nullptr) != 32) {
            break;
        }

        ret = true;

    } while (false);

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
    return ret;
}

ecdhe_context *new_ecdhe_context(curve_group_type curve) {
    if (curve == TLS_CURVE_X25519) {
        return __new_X25519_context();
    } else {
        return __new_curve_context(curve);
    }
}

void delete_ecdhe_context(ecdhe_context *ctx) {
    if (ctx) {
        object_delete(ctx);
    }
}

bool gen_ecdhe_shared_key(ecdhe_context *ctx,
                          const std::string &pubkey,
                          std::string &shared_key) {
    if (ctx->group == TLS_CURVE_X25519) {
        return __gen_X25519_shared_key(ctx, pubkey, shared_key);
    } else {
        return __gen_curve_shared_key(ctx, pubkey, shared_key);
    }
}

}  // namespace ssl
}  // namespace pump
