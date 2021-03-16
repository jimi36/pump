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

    void_ptr hash_create_context(hash_algorithm algorithm) {
        void_ptr ctx = nullptr;
#if defined(PUMP_HAVE_OPENSSL)
        switch (algorithm) {
        case HASH_SHA256:
            ctx = (uint8_t*)pump_malloc(sizeof(algorithm) + sizeof(SHA256_CTX)) + sizeof(algorithm);
            if (SHA256_Init((SHA256_CTX*)ctx) == 0) {
                pump_free(ctx);
                return nullptr;
            }
            break;
        case HASH_SHA384:
            ctx = (uint8_t*)pump_malloc(sizeof(algorithm) + sizeof(SHA512_CTX)) + sizeof(algorithm);
            if (SHA384_Init((SHA512_CTX*)ctx) == 0) {
                pump_free(ctx);
                return nullptr;
            }
            break;
        }
#endif
        return ctx;
    }

    void hash_destory_context(void_ptr ctx) {
        if (ctx) {
#if defined(PUMP_HAVE_OPENSSL)
            pump_free((uint8_t*)ctx - sizeof(hash_algorithm));
#endif
        }
    }

    bool hash_update(void_ptr ctx, const void_ptr data, int32_t data_len) {
#if defined(PUMP_HAVE_OPENSSL)
        PUMP_ASSERT(ctx);
        PUMP_ASSERT(data && data_len > 0);
        hash_algorithm algorithm = hash_algorithm((uint8_t*)ctx - sizeof(hash_algorithm));
        switch (algorithm)
        {
        case HASH_SHA256:
            if (SHA256_Update((SHA256_CTX*)ctx, data, data_len) == 1) {
                return true;
            }
            break;
        case HASH_SHA384:
            if (SHA256_Update((SHA256_CTX*)ctx, data, data_len) == 1) {
                return true;
            }
            break;
        }
#endif
        return false;
    }

    int32_t hash_result_length(hash_algorithm algorithm) {
        switch (algorithm)
        {
        case HASH_SHA256:
            return 32;
        case HASH_SHA384:
            return 48;
        } 
        return 0;
    }

    bool hash_result(void_ptr ctx, void_ptr result, int32_t result_len) {
#if defined(PUMP_HAVE_OPENSSL)
        PUMP_ASSERT(ctx);
        hash_algorithm algorithm = hash_algorithm((uint8_t*)ctx - sizeof(hash_algorithm));
        switch (algorithm)
        {
        case HASH_SHA256:
            PUMP_ASSERT(result && result_len >= 32);
            if (SHA256_Final((unsigned char*)result, (SHA256_CTX*)ctx) == 1) {
                return true;
            }
            break;
        case HASH_SHA384:
            PUMP_ASSERT(result && result_len >= 48);
            if (SHA384_Final((unsigned char*)result, (SHA512_CTX*)ctx) == 1) {
                return true;
            }
            break;
        } 
#endif
        return false;
    }

    hasher::hasher(hash_algorithm algorithm)
      : hash_ctx_(hash_create_context(algorithm)),
        result_length_(hash_result_length(algorithm)),
        algorithm_(algorithm) {
    }

    hasher::~hasher() {
        hash_destory_context(hash_ctx_);
    }

    bool hasher::update(void_ptr data, int32_t data_len) {
        if (!hash_ctx_) {
            return false;
        }
        return hash_update(hash_ctx_, data, data_len);
    }

    bool hasher::result(std::string &hash) {
        if (!hash_ctx_) {
            return false;
        }
        hash.resize(result_length_);
        return hash_result(hash_ctx_, (void_ptr)hash.data(), result_length_);
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

    bool generate_X25519_key_pair(ecdhe_key_pair *kp) {
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



}  // namespace ssl
}  // namespace pump