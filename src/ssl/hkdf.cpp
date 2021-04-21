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
#include "pump/ssl/hkdf.h"

#if defined(PUMP_HAVE_OPENSSL)
extern "C" {
#include <openssl/ssl.h>
#include <openssl/kdf.h>
}
#endif

#if defined(PUMP_HAVE_GNUTLS)
extern "C" {
#include <gnutls/gnutls.h>
}
#endif

namespace pump {
namespace ssl {

    bool hkdf_extract(
        hash_algorithm algo, 
        const std::string &salt,
        const std::string &key,
        std::string &out) {
        bool ret = false;
#if defined(PUMP_HAVE_OPENSSL)
        size_t out_len = 0;
        EVP_PKEY_CTX *pctx = nullptr;
        const EVP_MD *(*new_md_func)() = nullptr;
        
        if (algo == HASH_SHA256) {
            new_md_func = EVP_sha256;
        } else if (algo == HASH_SHA384) {
            new_md_func = EVP_sha384;
        } else {
            return false;
        }

        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (pctx == nullptr ||
            EVP_PKEY_derive_init(pctx) != 1 ||
            EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1 ||
            EVP_PKEY_CTX_set_hkdf_md(pctx, new_md_func()) != 1 ||
            EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), (int32_t)salt.size()) != 1 ||
            EVP_PKEY_CTX_set1_hkdf_key(pctx, key.data(), (int32_t)key.size()) != 1 || 
            EVP_PKEY_derive(pctx, nullptr, &out_len) != 1) {
            goto end;
        }

        out.resize(out_len);
        if (EVP_PKEY_derive(pctx, (uint8_t*)out.data(), &out_len) != 1) {
            goto end;
        }
        if (out.size() != out_len) {
            out.resize(out_len);
        }

        ret = true;

      end:
        if (pctx) {
            EVP_PKEY_CTX_free(pctx);
        }
#endif
        return ret;
    }

    bool hkdf_expand(
        hash_algorithm algo, 
        const std::string &key,
        const std::string &info,
        std::string &out) {
        bool ret = false;
#if defined(PUMP_HAVE_OPENSSL)
        size_t out_len = 0;
        EVP_PKEY_CTX *pctx = nullptr;
        const EVP_MD *(*new_md_func)() = nullptr;

        if (algo == HASH_SHA256) {
            new_md_func = EVP_sha256;
        } else if (algo == HASH_SHA384) {
            new_md_func = EVP_sha384;
        } else {
            return false;
        }

        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (pctx == nullptr ||
            EVP_PKEY_derive_init(pctx) != 1 ||
            EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1 ||
            EVP_PKEY_CTX_set_hkdf_md(pctx, new_md_func()) != 1 ||
            EVP_PKEY_CTX_set1_hkdf_key(pctx, key.data(), (int32_t)key.size()) != 1 ||
            EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), (int32_t)info.size()) != 1) {
            goto end;
        }

        out_len = out.size();
        if (EVP_PKEY_derive(pctx, (uint8_t*)out.data(), &out_len) <= 0) {
            goto end;
        }

        ret = true;

      end:
        if (pctx) {
            EVP_PKEY_CTX_free(pctx);
        }
#endif
        return ret;
    }

}
}