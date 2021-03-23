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
#include <openssl/kdf.h>
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
        defalut:
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

    bool update_hash(hash_context_ptr ctx, const std::string &data) {
        return update_hash(ctx, (const void_ptr)data.data(), (int32_t)data.size());
    }

    bool update_hash(hash_context_ptr ctx, const void_ptr data, int32_t data_len) {
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

    bool sum_hash(hash_context_ptr ctx, std::string &out) {
        out.resize(hash_digest_length(ctx->algo));
        return sum_hash(ctx, (void_ptr)out.data(), (int32_t)out.size());
    }

    bool sum_hash(hash_context_ptr ctx, void_ptr out, int32_t out_len) {
#if defined(PUMP_HAVE_OPENSSL)
        PUMP_ASSERT(ctx && ctx->ctx);
        PUMP_ASSERT(out && out_len >= hash_digest_length(ctx->algo));
        switch (ctx->algo)
        {
        case HASH_SHA1:
            return SHA1_Final((unsigned char*)out, (SHA_CTX*)ctx->ctx) == 1;
        case HASH_SHA224:
            return SHA224_Final((unsigned char*)out, (SHA256_CTX*)ctx->ctx) == 1;
        case HASH_SHA256:
            return SHA256_Final((unsigned char*)out, (SHA256_CTX*)ctx->ctx) == 1;
        case HASH_SHA384:
            return SHA384_Final((unsigned char*)out, (SHA512_CTX*)ctx->ctx) == 1;
        case HASH_SHA512:
            return SHA512_Final((unsigned char*)out, (SHA512_CTX*)ctx->ctx) == 1;
        }
#endif
        return false;
    }


}
}