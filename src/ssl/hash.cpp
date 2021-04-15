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
        void_ptr ctx;
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

    hash_context_ptr create_hash_context(hash_algorithm algo) {
        hash_context_ptr ctx = nullptr;
#if defined(PUMP_HAVE_OPENSSL)
        switch (algo) {
        case HASH_SHA1:
            ctx = (hash_context_ptr)pump_malloc(sizeof(hash_context) + sizeof(SHA_CTX));
            if (SHA1_Init((SHA_CTX*)ctx->_pctx) == 0) {
                pump_free(ctx);
                return nullptr;
            }
            break;
        case HASH_SHA224:
            ctx = (hash_context_ptr)pump_malloc(sizeof(hash_context) + sizeof(SHA256_CTX));
            if (SHA224_Init((SHA256_CTX*)ctx->_pctx) == 0) {
                pump_free(ctx);
                return nullptr;
            }
            break;
        case HASH_SHA256:
            ctx = (hash_context_ptr)pump_malloc(sizeof(hash_context) + sizeof(SHA256_CTX));
            if (SHA256_Init((SHA256_CTX*)ctx->_pctx) == 0) {
                pump_free(ctx);
                return nullptr;
            }
            break;
        case HASH_SHA384:
            ctx = (hash_context_ptr)pump_malloc(sizeof(hash_context) + sizeof(SHA512_CTX));
            if (SHA384_Init((SHA512_CTX*)ctx->_pctx) == 0) {
                pump_free(ctx);
                return nullptr;
            }
            break;
        case HASH_SHA512:
            ctx = (hash_context_ptr)pump_malloc(sizeof(hash_context) + sizeof(SHA512_CTX));
            if (SHA512_Init((SHA512_CTX*)ctx->_pctx) == 0) {
                pump_free(ctx);
                return nullptr;
            }
            break;
        default:
            PUMP_ASSERT(false);
            return nullptr;
        }
        ctx->ctx = ctx->_pctx;
        ctx->algo = algo;
#endif
        return ctx;
    }

    void free_hash_context(hash_context_ptr ctx) {
        if (ctx) {
#if defined(PUMP_HAVE_OPENSSL)
            pump_free(ctx);
#endif
        }
    }

    void reset_hash_context(hash_context_ptr ctx) {
        PUMP_ASSERT(ctx);
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

    bool update_hash(
        hash_context_ptr ctx, 
        const std::string &data) {
        return update_hash(ctx, (const uint8_t*)data.data(), (int32_t)data.size());
    }

    bool update_hash(
        hash_context_ptr ctx, 
        const uint8_t *data, 
        int32_t data_len) {
#if defined(PUMP_HAVE_OPENSSL)
        PUMP_ASSERT(ctx && ctx->ctx);
        PUMP_ASSERT(data && data_len > 0);
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
        hash_context_ptr ctx, 
        uint8_t *out, 
        int32_t out_len) {
#if defined(PUMP_HAVE_OPENSSL)
        PUMP_ASSERT(ctx && ctx->ctx);
        PUMP_ASSERT(out && out_len >= hash_digest_length(ctx->algo));
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

    std::string sum_hash(hash_context_ptr ctx) {
        std::string output(hash_digest_length(ctx->algo), 0);
        PUMP_DEBUG_CHECK(sum_hash(ctx, (uint8_t*)output.data(), (int32_t)output.size()));
        return std::forward<std::string>(output);
    }

    std::string sum_hmac(
        hash_algorithm algo,
        const std::string &key,
        const std::string &input) {
        std::string out;
#if defined(PUMP_HAVE_OPENSSL)
        const EVP_MD *md = nullptr;
        switch (algo)
        {
        case HASH_SHA1:
            md = EVP_sha1();
            break;
        case HASH_SHA224:
            md = EVP_sha224();
            break;
        case HASH_SHA256:
            md = EVP_sha256();
            break;
        case HASH_SHA384:
            md = EVP_sha384();
            break;
        case HASH_SHA512:
            md = EVP_sha512();
            break;
        }

        uint32_t out_len = (uint32_t)hash_digest_length(algo);
        out.resize(out_len);

        uint8_t *ret = HMAC(
                        md, 
                        (c_void_ptr)key.data(), 
                        (int32_t)key.size(),
                        (const uint8_t*)input.data(), 
                        input.size(),
                        (uint8_t*)out.data(), 
                        &out_len);
        PUMP_ASSERT(ret != nullptr);
#endif
        return std::forward<std::string>(out);
    }


}
}