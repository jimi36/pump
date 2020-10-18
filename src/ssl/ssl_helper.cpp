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

    void_ptr create_tls_client_certificate() {
#if defined(PUMP_HAVE_GNUTLS)
        gnutls_certificate_credentials_t xcred;
        if (gnutls_certificate_allocate_credentials(&xcred) != 0) {
            PUMP_ERR_LOG(
                "ssl::create_tls_client_certificate: "
                "gnutls_certificate_allocate_credentials failed\n");
            return nullptr;
        }
        return xcred;
#elif defined(PUMP_HAVE_OPENSSL)
        SSL_CTX *xcred = SSL_CTX_new(TLS_client_method());
        if (!xcred) {
            PUMP_ERR_LOG("ssl::create_tls_client_certificate: SSL_CTX_new failed\n");
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
        int32 ret = gnutls_certificate_allocate_credentials(&xcred);
        if (ret != 0) {
            PUMP_ERR_LOG(
                "ssl::generate_tls_certificate_by_file: "
                "gnutls_certificate_allocate_credentials failed");
            return nullptr;
        }

        ret = gnutls_certificate_set_x509_key_file(
            xcred, cert.c_str(), key.c_str(), GNUTLS_X509_FMT_PEM);
        if (ret != 0) {
            PUMP_ERR_LOG(
                "ssl::generate_tls_certificate_by_file: "
                "gnutls_certificate_set_x509_key_file failed");
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
            PUMP_ERR_LOG("ssl::create_tls_certificate_by_file: SSL_CTX_new failed\n");
            return nullptr;
        }

        //SSL_CTX_set_options(xcred, SSL_EXT_TLS1_3_ONLY);
        //SSL_CTX_set_ecdh_auto(xcred, 1);

        /* Set the key and cert */
        if (SSL_CTX_use_certificate_file(xcred, cert.c_str(), SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(xcred, key.c_str(), SSL_FILETYPE_PEM) <= 0) {
            SSL_CTX_free(xcred);
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
        int32 ret = gnutls_certificate_allocate_credentials(&xcred);
        if (ret != 0) {
            PUMP_ERR_LOG(
                "ssl::generate_tls_certificate_by_buffer: "
                "gnutls_certificate_allocate_credentials failed");
            return nullptr;
        }

        gnutls_datum_t gnutls_cert;
        gnutls_cert.data = (unsigned char *)cert.data();
        gnutls_cert.size = (unsigned int)cert.size();

        gnutls_datum_t gnutls_key;
        gnutls_key.data = (unsigned char *)key.data();
        gnutls_key.size = (unsigned int)key.size();

        int32 ret2 = gnutls_certificate_set_x509_key_mem(
            xcred, &gnutls_cert, &gnutls_key, GNUTLS_X509_FMT_PEM);
        if (ret2 != 0) {
            PUMP_ERR_LOG(
                "ssl::generate_tls_certificate_by_buffer: "
                "gnutls_certificate_set_x509_key_mem failed");
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
            PUMP_ERR_LOG("ssl::create_tls_certificate_by_buffer: SSL_CTX_new failed\n");
            return nullptr;
        }

        SSL_CTX_set_options(xcred, SSL_EXT_TLS1_3_ONLY);
        SSL_CTX_set_ecdh_auto(xcred, 1);

        BIO *cert_bio = BIO_new_mem_buf((void *)cert.c_str(), -1);
        X509 *x509_cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
        BIO_free(cert_bio);
        if (!x509_cert) {
            SSL_CTX_free(xcred);
            return nullptr;
        }

        BIO *key_bio = BIO_new_mem_buf((void *)key.c_str(), -1);
        EVP_PKEY *evp_key = PEM_read_bio_PrivateKey(key_bio, NULL, 0, NULL);
        BIO_free(key_bio);
        // const unsigned char *pkey = (const unsigned char *)key.c_str();
        //EVP_PKEY *evp_key = d2i_AutoPrivateKey(NULL, &pkey, (long)key.size());
        if (!evp_key) {
            SSL_CTX_free(xcred);
            X509_free(x509_cert);
            return nullptr;
        }

        /* Set the key and cert */
        if (SSL_CTX_use_certificate(xcred, x509_cert) <= 0 ||
            SSL_CTX_use_PrivateKey(xcred, evp_key) <= 0) {
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
            SSL_CTX_free((SSL_CTX *)xcred);
        }
#endif
    }

}  // namespace ssl
}  // namespace pump