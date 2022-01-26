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
#include "pump/ssl/hash.h"

#if defined(PUMP_HAVE_OPENSSL)
extern "C" {
#include <openssl/ssl.h>
#include <openssl/hmac.h>
}
#endif

#if defined(PUMP_HAVE_GNUTLS)
extern "C" {
#include <gnutls/gnutls.h>
}
#endif

namespace pump {
namespace ssl {

    struct hash_context {
        hash_algorithm algo;
        void *ctx;
        int8_t _pctx[0];
    };

    int32_t hash_digest_length(hash_algorithm algo) {
        PUMP_ASSERT(algo > HASH_UNKNOWN && algo <= HASH_SHA512);
        const static int32_t digest_lengths[] = {
            0,  // HASH_UNKNOWN
            20, // HASH_SHA1
            28, // HASH_SHA224
            32, // HASH_SHA256
            48, // HASH_SHA384
            64  // HASH_SHA512
        };
        return digest_lengths[algo];
    }

    hash_context* create_hash_context(hash_algorithm algo) {
        hash_context *ctx = nullptr;
#if defined(PUMP_HAVE_OPENSSL)
        switch (algo) {
        case HASH_SHA1:
            ctx = (hash_context*)pump_malloc(sizeof(hash_context) + sizeof(SHA_CTX));
            if (ctx == nullptr) {
                return nullptr;
            } else if (SHA1_Init((SHA_CTX*)ctx->_pctx) == 0) {
                pump_free(ctx);
                return nullptr;
            }
            break;
        case HASH_SHA224:
            ctx = (hash_context*)pump_malloc(sizeof(hash_context) + sizeof(SHA256_CTX));
            if (ctx == nullptr) {
                return nullptr;
            } else if (SHA224_Init((SHA256_CTX*)ctx->_pctx) == 0) {
                pump_free(ctx);
                return nullptr;
            }
            break;
        case HASH_SHA256:
            ctx = (hash_context*)pump_malloc(sizeof(hash_context) + sizeof(SHA256_CTX));
            if (ctx == nullptr) {
                return nullptr;
            } else if (SHA256_Init((SHA256_CTX*)ctx->_pctx) == 0) {
                pump_free(ctx);
                return nullptr;
            }
            break;
        case HASH_SHA384:
            ctx = (hash_context*)pump_malloc(sizeof(hash_context) + sizeof(SHA512_CTX));
            if (ctx == nullptr) {
                return nullptr;
            } else if (SHA384_Init((SHA512_CTX*)ctx->_pctx) == 0) {
                pump_free(ctx);
                return nullptr;
            }
            break;
        case HASH_SHA512:
            ctx = (hash_context*)pump_malloc(sizeof(hash_context) + sizeof(SHA512_CTX));
            if (ctx == nullptr) {
                return nullptr;
            } else if (SHA512_Init((SHA512_CTX*)ctx->_pctx) == 0) {
                pump_free(ctx);
                return nullptr;
            }
            break;
        default:
            return nullptr;
        }
        ctx->ctx = ctx->_pctx;
        ctx->algo = algo;
#endif
        return ctx;
    }

    void free_hash_context(hash_context *ctx) {
        PUMP_ASSERT(ctx != nullptr);
        if (ctx != nullptr) {
#if defined(PUMP_HAVE_OPENSSL)
            pump_free(ctx);
#endif
        }
    }

    void reset_hash_context(hash_context *ctx) {
        PUMP_ASSERT(ctx != nullptr);
#if defined(PUMP_HAVE_OPENSSL)
        switch (ctx->algo)
        {
        case HASH_SHA1:
            SHA1_Init((SHA_CTX*)ctx->ctx);
            return;
        case HASH_SHA224:
            SHA224_Init((SHA256_CTX*)ctx->ctx);
            return;
        case HASH_SHA256:
            SHA256_Init((SHA256_CTX*)ctx->ctx);
            return;
        case HASH_SHA384:
            SHA384_Init((SHA512_CTX*)ctx->ctx);
            return;
        case HASH_SHA512:
            SHA512_Init((SHA512_CTX*)ctx->ctx);
            return;
        }  
#endif
    }

    bool update_hash(hash_context *ctx, const std::string &data) {
        return update_hash(ctx, (const uint8_t*)data.data(), (int32_t)data.size());
    }

    bool update_hash(
        hash_context *ctx, 
        const uint8_t *data, 
        int32_t data_len) {
        PUMP_ASSERT(ctx != nullptr);
#if defined(PUMP_HAVE_OPENSSL)
        switch (ctx->algo)
        {
        case HASH_SHA1:
            return SHA1_Update((SHA_CTX*)ctx->ctx, data, data_len) == 1;
        case HASH_SHA224:
            return SHA224_Update((SHA256_CTX*)ctx->ctx, data, data_len) == 1;
        case HASH_SHA256:
            return SHA256_Update((SHA256_CTX*)ctx->ctx, data, data_len) == 1;
        case HASH_SHA384:
            return SHA384_Update((SHA512_CTX*)ctx->ctx, data, data_len) == 1;
        case HASH_SHA512:
            return SHA512_Update((SHA512_CTX*)ctx->ctx, data, data_len) == 1;
        }
#endif
        return false;
    }

    bool sum_hash(
        hash_context *ctx, 
        uint8_t *out, 
        int32_t out_len) {
        PUMP_ASSERT(ctx != nullptr);
#if defined(PUMP_HAVE_OPENSSL)
        if (out == nullptr || out_len < hash_digest_length(ctx->algo)) {
            return false;
        }
        switch (ctx->algo)
        {
        case HASH_SHA1:
            return SHA1_Final((uint8_t*)out, (SHA_CTX*)ctx->ctx) == 1;
        case HASH_SHA224:
            return SHA224_Final((uint8_t*)out, (SHA256_CTX*)ctx->ctx) == 1;
        case HASH_SHA256:
            return SHA256_Final((uint8_t*)out, (SHA256_CTX*)ctx->ctx) == 1;
        case HASH_SHA384:
            return SHA384_Final((uint8_t*)out, (SHA512_CTX*)ctx->ctx) == 1;
        case HASH_SHA512:
            return SHA512_Final((uint8_t*)out, (SHA512_CTX*)ctx->ctx) == 1;
        }
#endif
        return false;
    }

    std::string sum_hash(hash_context *ctx) {
        std::string out(hash_digest_length(ctx->algo), 0);
        if (!sum_hash(ctx, (uint8_t*)out.data(), (int32_t)out.size())) {
            PUMP_WARN_LOG("sum hash failed");
        }
        return out;
    }

    std::string sum_hmac(
        hash_algorithm algo,
        const std::string &key,
        const std::string &input) {
        std::string out;
#if defined(PUMP_HAVE_OPENSSL)
        do {
            uint32_t out_len = (uint32_t)hash_digest_length(algo);
            if (out_len == 0) {
                break;
            }

            const EVP_MD *(*new_md_func)() = nullptr;
            if (algo == HASH_SHA1) {
                new_md_func = EVP_sha1;
            } else if (algo == HASH_SHA224) {
                new_md_func = EVP_sha224;
            } else if (algo == HASH_SHA256) {
                new_md_func = EVP_sha256;
            } else if (algo == HASH_SHA384) {
                new_md_func = EVP_sha384;
            } else if (algo == HASH_SHA512) {
                new_md_func = EVP_sha512;
            }

            if (new_md_func != nullptr) {
                out.resize(out_len);
                PUMP_ABORT_WITH_LOG(
                    HMAC(new_md_func(), 
                        (const void*)key.data(), 
                        (int32_t)key.size(),
                        (const uint8_t*)input.data(), 
                        input.size(),
                        (uint8_t*)out.data(), 
                        &out_len) == nullptr,
                    ""); 
            }
        } while(false);
#endif
        return out;
    }

}
}