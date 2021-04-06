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
#include "pump/ssl/cert.h"

#if defined(PUMP_HAVE_OPENSSL)
extern "C" {
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
}
#endif

#if defined(PUMP_HAVE_GNUTLS)
extern "C" {
#include <gnutls/gnutls.h>
}
#endif

namespace pump {
namespace ssl {

    std::string generate_x509_certificate(signature_scheme scheme) {
        std::string out;
#if defined(PUMP_HAVE_OPENSSL)
        X509* cert = nullptr;
        switch (scheme) {
        case TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256:
        case TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384:
        case TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512:
            {
                EC_KEY *eckey = nullptr;
                if (scheme == TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256) {
                    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                } else if (scheme == TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384) {
                    eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
                } else if (scheme == TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512) {
                    eckey = EC_KEY_new_by_curve_name(NID_secp521r1);
                }
                PUMP_ASSERT(eckey != nullptr);
                EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
                PUMP_DEBUG_EQUAL_CHECK(EC_KEY_generate_key(eckey), 1);

                EVP_PKEY* pkey = EVP_PKEY_new();
                PUMP_DEBUG_EQUAL_CHECK(EVP_PKEY_assign_EC_KEY(pkey, eckey), 1);
                
                cert = X509_new();
                PUMP_ASSERT(cert != nullptr);
                /* REALLY shouldn't use fixed serial if DN isn't unique */
                PUMP_DEBUG_EQUAL_CHECK(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1), 1);
                PUMP_DEBUG_NOEQUAL_CHECK(X509_gmtime_adj(X509_get_notBefore(cert), 0), nullptr);
                PUMP_DEBUG_NOEQUAL_CHECK(X509_gmtime_adj(X509_get_notAfter(cert), 365L * 86400), nullptr);
                PUMP_DEBUG_EQUAL_CHECK(X509_set_pubkey(cert, pkey), 1);

                X509_NAME* name = X509_get_subject_name(cert);
                X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (uint8_t*)"CA", -1, -1, 0);
                X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (uint8_t*)"MyCompany Inc.", -1, -1, 0);
                X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (uint8_t*)"localhost", -1, -1, 0);
                X509_set_issuer_name(cert, name);

                //EC_KEY_free(eckey);
                EVP_PKEY_free(pkey);
            }
            break;
        default:
            break;
        }

        if (cert) {
            out = read_x509_certificate_pem(cert);
            //out_cert.resize(i2d_X509(cert, nullptr));
            //uint8_t* data = (uint8_t*)out_cert.data();
            //PUMP_DEBUG_EQUAL_CHECK(i2d_X509(cert, &data), (int32_t)out_cert.size());
            X509_free(cert);
        }
#endif
        return std::forward<std::string>(out);
    }

    std::string read_x509_certificate_pem(x509_certificate_ptr cert) {
        std::string out;
#if defined(PUMP_HAVE_OPENSSL)
        BIO *bio = BIO_new(BIO_s_mem());
        PUMP_ASSERT(bio != nullptr);
        //PEM_read_bio_X509(bio, (X509**)&cert, NULL, NULL);
        PEM_write_bio_X509(bio, (X509*)cert);
        BUF_MEM *buf = nullptr;
        BIO_get_mem_ptr(bio, &buf);
        out.assign(buf->data, buf->length);
        BIO_free(bio);
#endif
        return std::forward<std::string>(out);
    }

    std::string read_x509_certificate_raw(x509_certificate_ptr cert) {
        std::string out;
#if defined(PUMP_HAVE_OPENSSL)
        out.resize(i2d_X509((X509*)cert, nullptr));
        uint8_t *buffer = (uint8_t*)out.data();
        i2d_X509((X509*)cert, &buffer);
#endif
        return std::forward<std::string>(out);
    }

    x509_certificate_ptr load_x509_certificate(const std::string &data) {
        return load_x509_certificate((const uint8_t*)data.data(), (int32_t)data.size());
    }

    x509_certificate_ptr load_x509_certificate(const uint8_t *data, int32_t size) {
#if defined(PUMP_HAVE_OPENSSL)
        BIO *bio = BIO_new_mem_buf((c_void_ptr)data, size);
        if (bio == nullptr) {
            return nullptr;
        }
        X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        return cert;
        //return d2i_X509(NULL, &data, size);
#else
        return nullptr;
#endif
    }

    void free_x509_certificate(x509_certificate_ptr cert) {
#if defined(PUMP_HAVE_OPENSSL)
        X509_free((X509*)cert);
#endif
    }

    signature_scheme get_x509_signature_scheme(x509_certificate_ptr cert) {
#if defined(PUMP_HAVE_OPENSSL)
        EVP_PKEY *pkey = X509_get_pubkey((X509*)cert);
        switch (EVP_PKEY_base_id(pkey)) {
        case EVP_PKEY_RSA:
        {
            int32_t pkey_size = EVP_PKEY_size(pkey);
            if (pkey_size == 256) {
                return TLS_SIGN_SCHE_PSSWITHSHA256;
            } else if (pkey_size == 384) {
                return TLS_SIGN_SCHE_PSSWITHSHA384;
            } else if (pkey_size == 512) {
                return TLS_SIGN_SCHE_PSSWITHSHA512;
            }
            break;
        }
        case EVP_PKEY_EC:
        {
            EC_KEY *key = EVP_PKEY_get1_EC_KEY(pkey);
            int32_t curve = EC_GROUP_get_curve_name(EC_KEY_get0_group(key));
            if (curve == NID_X9_62_prime256v1) {
                return TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256;
            } else if (curve == NID_secp384r1) {
                return TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384;
            } else if (curve == NID_secp521r1) {
                return TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512;
            }
            break;
        }
        case EVP_PKEY_ED25519:
            return TLS_SIGN_SCHE_ED25519;
        }
#endif
        return TLS_SIGN_SCHE_UNKNOWN;
    }

    bool verify_x509_certificates(std::vector<x509_certificate_ptr> &certs) {
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

    void_ptr create_tls_certificate_by_file(
        bool client,
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

    void_ptr create_tls_certificate_by_buffer(
        bool client,
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

}  // namespace ssl
}  // namespace pump