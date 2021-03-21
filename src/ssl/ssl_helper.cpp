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
#include "pump/ssl/ssl_helper.h"

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
        void_ptr ctx;
        hash_algorithm algorithm;
    };

    int32_t hash_size(hash_algorithm algorithm) {
        switch (algorithm)
        {
        case HASH_SHA256:
            return 32;
        case HASH_SHA384:
            return 48;
        } 
        return 0;
    }

    hash_context_ptr hash_new(hash_algorithm algorithm) {
        hash_context_ptr ctx = nullptr;
#if defined(PUMP_HAVE_OPENSSL)
        switch (algorithm) {
        case HASH_SHA256:
            ctx = (hash_context_ptr)pump_malloc(sizeof(hash_context));
            ctx->ctx = pump_malloc(sizeof(SHA256_CTX));
            if (SHA256_Init((SHA256_CTX*)ctx) == 0) {
                pump_free(ctx->ctx);
                pump_free(ctx);
                return nullptr;
            }
            break;
        case HASH_SHA384:
            ctx = (hash_context_ptr)pump_malloc(sizeof(hash_context));
            ctx->ctx = pump_malloc(sizeof(SHA512_CTX));
            if (SHA384_Init((SHA512_CTX*)ctx) == 0) {
                pump_free(ctx->ctx);
                pump_free(ctx);
                return nullptr;
            }
            break;
        defalut:
            return nullptr;
        }
        ctx->algorithm = algorithm;
#endif
        return ctx;
    }

    void hash_delete(hash_context_ptr ctx) {
        if (ctx) {
#if defined(PUMP_HAVE_OPENSSL)
            pump_free(ctx->ctx);
            pump_free(ctx);
#endif
        }
    }

    bool hash_update(hash_context_ptr ctx, const void_ptr data, int32_t data_len) {
#if defined(PUMP_HAVE_OPENSSL)
        PUMP_ASSERT(ctx && ctx->ctx);
        PUMP_ASSERT(data && data_len > 0);
        switch (ctx->algorithm)
        {
        case HASH_SHA256:
            return SHA256_Update((SHA256_CTX*)ctx->ctx, data, data_len) == 1;
        case HASH_SHA384:
            return SHA256_Update((SHA256_CTX*)ctx->ctx, data, data_len) == 1;
        }
#endif
        return false;
    }

    bool hash_result(hash_context_ptr ctx, void_ptr out, int32_t out_len) {
#if defined(PUMP_HAVE_OPENSSL)
        PUMP_ASSERT(ctx && ctx->ctx);
        PUMP_ASSERT(out && out_len >= hash_size(ctx->algorithm));
        switch (ctx->algorithm)
        {
        case HASH_SHA256:
            return SHA256_Final((unsigned char*)out, (SHA256_CTX*)ctx->ctx) == 1;
        case HASH_SHA384:
            return SHA384_Final((unsigned char*)out, (SHA512_CTX*)ctx->ctx) == 1;
        }
#endif
        return false;
    }

    bool hkdf_extract(hash_algorithm algorithm, 
                      const std::string &salt,
                      const std::string &key,
                      std::string &out) {
#if defined(PUMP_HAVE_OPENSSL)
        const EVP_MD *(*new_md_func)(void);
        if (algorithm == HASH_SHA256) {
            new_md_func = EVP_sha256;
        } else if (algorithm == HASH_SHA384) {
            new_md_func = EVP_sha384;
        } else {
            return false;
        }
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        if (!pctx) {
            return false;
        }

        if (EVP_PKEY_derive_init(pctx) <= 0 ||
            EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0 ||
            EVP_PKEY_CTX_set_hkdf_md(pctx, new_md_func()) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_key(pctx, key.data(), key.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }

        size_t out_len = 0;
        if (EVP_PKEY_derive(pctx, NULL, &out_len) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
        out.resize(out_len);
        if (EVP_PKEY_derive(pctx, (uint8_t*)out.data(), &out_len) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }

        EVP_PKEY_CTX_free(pctx);

        return true;
#else
        return false;
#endif
    }

    bool hkdf_expand(hash_algorithm algorithm, 
                     const std::string &key,
                     const std::string &info,
                     std::string &out) {
#if defined(PUMP_HAVE_OPENSSL)
        const EVP_MD *(*new_md_func)(void);
        if (algorithm == HASH_SHA256) {
            new_md_func = EVP_sha256;
        } else if (algorithm == HASH_SHA384) {
            new_md_func = EVP_sha384;
        } else {
            return false;
        }
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        if (!pctx) {
            return false;
        }

        if (EVP_PKEY_derive_init(pctx) <= 0 ||
            EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 ||
            EVP_PKEY_CTX_set_hkdf_md(pctx, new_md_func()) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_key(pctx, key.data(), key.size()) <= 0 ||
            EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }

        size_t out_len = out.size();
        if (EVP_PKEY_derive(pctx, (uint8_t*)out.data(), &out_len) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }

        EVP_PKEY_CTX_free(pctx);

        return true;
#else
        return false;
#endif
    }

    void_ptr x509_certificate_new(void_ptr data, int32_t size) {
#if defined(PUMP_HAVE_OPENSSL)
        uint8_t *tmp = (uint8_t*)data;
        return d2i_X509(NULL, &tmp, size);
#else
        return nullptr;
#endif
    }

    void x509_certificate_delete(void_ptr cert) {
#if defined(PUMP_HAVE_OPENSSL)
        X509_free((X509*)cert);
#endif
    }

    bool x509_certificate_verify(std::vector<void_ptr> &certs) {
#if defined(PUMP_HAVE_OPENSSL)
        X509_STORE *store = X509_STORE_new();
        for (int32_t i = 1; i < (int32_t)certs.size(); i++) {
            X509_STORE_add_cert(store, (X509*)certs[i]);
        }

        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx, store, (X509*)certs[0], NULL);
        int32_t ret = X509_verify_cert(ctx);

        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);

        return ret == 1;
#else
        return false;
#endif
    }

    void_ptr create_tls_client_certificate() {
#if defined(PUMP_HAVE_GNUTLS)
        gnutls_certificate_credentials_t xcred;
        if (gnutls_certificate_allocate_credentials(&xcred) != 0) {
            PUMP_ERR_LOG(
                "ssl_helper: create tls client certificate failed for gnutls_certificate_allocate_credentials failed");
            return nullptr;
        }
        return xcred;
#elif defined(PUMP_HAVE_OPENSSL)
        SSL_CTX *xcred = SSL_CTX_new(TLS_client_method());
        if (!xcred) {
            PUMP_ERR_LOG(
                "ssl_helper: create tls_client certificate failed for SSL_CTX_new failed");
            return nullptr;
        }
        SSL_CTX_set_options(xcred, SSL_EXT_TLS1_3_ONLY);
        return xcred;
#else
        return nullptr;
#endif
    }

    void_ptr create_tls_certificate_by_file(bool client,
                                            const std::string &cert,
                                            const std::string &key) {
#if defined(PUMP_HAVE_GNUTLS)
        gnutls_certificate_credentials_t xcred;
        int32_t ret = gnutls_certificate_allocate_credentials(&xcred);
        if (ret != 0) {
            PUMP_ERR_LOG(
                "ssl_helper: create tls certificate by file failed for gnutls_certificate_allocate_credentials failed");
            return nullptr;
        }

        ret = gnutls_certificate_set_x509_key_file(
            xcred, cert.c_str(), key.c_str(), GNUTLS_X509_FMT_PEM);
        if (ret != 0) {
            PUMP_ERR_LOG(
                "ssl_helper: create tls certificate by file failed for gnutls_certificate_set_x509_key_file failed");
            gnutls_certificate_free_credentials(xcred);
            return nullptr;
        }

        return xcred;
#elif defined(PUMP_HAVE_OPENSSL)
        SSL_CTX *xcred = nullptr;
        if (client) {
            xcred = SSL_CTX_new(TLS_client_method());
        } else {
            xcred = SSL_CTX_new(TLS_server_method());
        }
        if (!xcred) {
            PUMP_ERR_LOG(
                "ssl_helper: create tls certificate by file failed for SSL_CTX_new failed");
            return nullptr;
        }

        /* Set the key and cert */
        if (SSL_CTX_use_certificate_file(xcred, cert.c_str(), SSL_FILETYPE_PEM) <= 0) {
            SSL_CTX_free(xcred);
            PUMP_ERR_LOG(
                "ssl_helper: create tls certificate by file failed for SSL_CTX_use_certificate_file failed");
            return nullptr;
        }
        if (SSL_CTX_use_PrivateKey_file(xcred, key.c_str(), SSL_FILETYPE_PEM) <= 0) {
            SSL_CTX_free(xcred);
            PUMP_ERR_LOG(
                "ssl_helper: create tls certificate by file failed for SSL_CTX_use_PrivateKey_file failed");
            return nullptr;
        }
        return xcred;
#else
        return nullptr;
#endif
    }

    void_ptr create_tls_certificate_by_buffer(bool client,
                                              const std::string &cert,
                                              const std::string &key) {
#if defined(PUMP_HAVE_GNUTLS)
        gnutls_certificate_credentials_t xcred;
        int32_t ret = gnutls_certificate_allocate_credentials(&xcred);
        if (ret != 0) {
            PUMP_ERR_LOG(
                "ssl_helper: create tls certificate by buffer failed for gnutls_certificate_allocate_credentials failed");
            return nullptr;
        }

        gnutls_datum_t gnutls_cert;
        gnutls_cert.data = (uint8_t*)cert.data();
        gnutls_cert.size = (uint32_t)cert.size();

        gnutls_datum_t gnutls_key;
        gnutls_key.data = (uint8_t*)key.data();
        gnutls_key.size = (uint32_t)key.size();

        int32_t ret2 = gnutls_certificate_set_x509_key_mem(xcred, &gnutls_cert, &gnutls_key, GNUTLS_X509_FMT_PEM);
        if (ret2 != 0) {
            PUMP_ERR_LOG(
                "ssl_helper: create tls certificate by buffer failed for gnutls_certificate_set_x509_key_mem failed");
            gnutls_certificate_free_credentials(xcred);
            return nullptr;
        }

        return xcred;
#elif defined(PUMP_HAVE_OPENSSL)
        SSL_CTX *xcred = nullptr;
        if (client) {
            xcred = SSL_CTX_new(TLS_client_method());
        } else {
            xcred = SSL_CTX_new(TLS_server_method());
        }
        if (!xcred) {
            PUMP_ERR_LOG(
                "ssl_helper: create tls certificate by buffer failed for SSL_CTX_new failed");
            return nullptr;
        }

        BIO *cert_bio = BIO_new_mem_buf((void_ptr)cert.c_str(), -1);
        X509 *x509_cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
        BIO_free(cert_bio);
        if (!x509_cert) {
            PUMP_ERR_LOG(
                "ssl_helper: create tls certificate by buffer failed for PEM_read_bio_X509 failed");
            SSL_CTX_free(xcred);
            return nullptr;
        }

        BIO *key_bio = BIO_new_mem_buf((void_ptr)key.c_str(), -1);
        EVP_PKEY *evp_key = PEM_read_bio_PrivateKey(key_bio, NULL, 0, NULL);
        BIO_free(key_bio);
        if (!evp_key) {
            PUMP_ERR_LOG(
                "ssl_helper: create tls certificate by buffer failed for PEM_read_bio_PrivateKey failed");
            SSL_CTX_free(xcred);
            X509_free(x509_cert);
            return nullptr;
        }

        /* Set the key and cert */
        if (SSL_CTX_use_certificate(xcred, x509_cert) <= 0 ||
            SSL_CTX_use_PrivateKey(xcred, evp_key) <= 0) {
            PUMP_ERR_LOG(
                "ssl_helper: create tls certificate by buffer failed for SSL_CTX_use_PrivateKey failed");
            SSL_CTX_free(xcred);
            X509_free(x509_cert);
            EVP_PKEY_free(evp_key);
            return nullptr;
        }

        X509_free(x509_cert);
        EVP_PKEY_free(evp_key);

        return xcred;
#else
        return nullptr;
#endif
    }

    void destory_tls_certificate(void_ptr xcred) {
#if defined(PUMP_HAVE_GNUTLS)
        if (xcred) {
            gnutls_certificate_free_credentials((gnutls_certificate_credentials_t)xcred);
        }
#elif defined(PUMP_HAVE_OPENSSL)
        if (xcred) {
            SSL_CTX_free((SSL_CTX*)xcred);
        }
#endif
    }

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

}  // namespace ssl
}  // namespace pump