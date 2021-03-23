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
#include "pump/ssl/ecdhe.h"

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

    bool X25519_init(key_pair *kp) {
#if defined(PUMP_HAVE_OPENSSL)
        // Create and init context.
        EVP_PKEY_CTX *pctx = NULL;
        if ((pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL)) == NULL) {
            return false;
        }
        if (EVP_PKEY_keygen_init(pctx) == 0) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }

        // Generate the key.
        EVP_PKEY *pkey = NULL;
        if (EVP_PKEY_keygen(pctx, &pkey) == 0) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
        EVP_PKEY_CTX_free(pctx);

        // Get private key.
        char *key = NULL;
        int32_t key_len = 0;
        BIO *mem_bio = BIO_new(BIO_s_mem());
        if (PEM_write_bio_PrivateKey(mem_bio, pkey, NULL,NULL, 0, NULL, NULL) == 0) {
            EVP_PKEY_free(pkey);
            BIO_free(mem_bio);
            return false;
        }
        key_len = BIO_get_mem_data(mem_bio, &key);
        kp->prikey.assign(key, key_len);

        // Get public key.
        key = NULL;
        key_len = 0;
        BIO_reset(mem_bio);
        if (PEM_write_bio_PUBKEY(mem_bio, pkey) == 0) {
            EVP_PKEY_free(pkey);
            BIO_free(mem_bio);
            return false;
        }
        key_len = BIO_get_mem_data(mem_bio, &key);
        kp->pubkey.assign(key, key_len);

        EVP_PKEY_free(pkey);

        return true;
#else
        return false;
#endif
    }

    bool X25519_device(key_pair *kp, const std::string &data, std::string &out) {
#if defined(PUMP_HAVE_OPENSSL)
        // Load peer public key.
        BIO *pub_bio = BIO_new_mem_buf(data.data(), data.size());
        EVP_PKEY *pub_key = PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL);
        BIO_free(pub_bio);
        if (!pub_key) {
            return false;
        }

        // Load private key.
        BIO *pri_bio = BIO_new_mem_buf(kp->prikey.data(), kp->prikey.size());
        EVP_PKEY *pri_key = PEM_read_bio_PrivateKey(pri_bio, NULL, NULL, NULL);
        BIO_free(pri_bio);
        if (!pri_key) {
            EVP_PKEY_free(pub_key);
            return false;
        }

        // Create context.
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pri_key, NULL);
        if (!ctx) {
            EVP_PKEY_free(pub_key);
            EVP_PKEY_free(pri_key);
            return false;
        }
        
        if (EVP_PKEY_derive_init(ctx) <= 0 ||
            EVP_PKEY_derive_set_peer(ctx, pub_key) <= 0) {
            EVP_PKEY_free(pub_key);
            EVP_PKEY_free(pri_key);
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        size_t out_len = 0;
        if (EVP_PKEY_derive(ctx, NULL, &out_len) <= 0) {
            EVP_PKEY_free(pub_key);
            EVP_PKEY_free(pri_key);
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        out.resize(out_len);
        if (EVP_PKEY_derive(ctx, (uint8_t*)out.data(), &out_len) <= 0) {
		    EVP_PKEY_free(pub_key);
            EVP_PKEY_free(pri_key);
            EVP_PKEY_CTX_free(ctx);
            return false;
	    }

        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(pri_key);
        EVP_PKEY_CTX_free(ctx);

        return true;
#else
        return false;
#endif
    }

}
}