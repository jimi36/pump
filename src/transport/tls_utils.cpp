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
#include "pump/memory.h"
#include "pump/transport/tls_utils.h"

#if defined(PUMP_HAVE_TLS)
extern "C" {
#include <openssl/ssl.h>
}
#endif

namespace pump {
namespace transport {

tls_credentials new_client_tls_credentials() {
#if defined(PUMP_HAVE_TLS)
    SSL_CTX *xcred = SSL_CTX_new(TLS_client_method());
    if (xcred == nullptr) {
        pump_warn_log("create client tls certificate context failed");
        return nullptr;
    }
    SSL_CTX_set_options(xcred, SSL_EXT_TLS1_3_ONLY);
    return xcred;
#else
    return nullptr;
#endif
}

tls_credentials load_tls_credentials_from_file(
    bool client,
    const std::string &cert,
    const std::string &key) {
#if defined(PUMP_HAVE_TLS)
    SSL_CTX *xcred = nullptr;
    if (client) {
        xcred = SSL_CTX_new(TLS_client_method());
    } else {
        xcred = SSL_CTX_new(TLS_server_method());
    }
    if (xcred == nullptr) {
        return nullptr;
    }

    if (SSL_CTX_use_certificate_file(xcred, cert.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(xcred, key.c_str(), SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(xcred);
        return nullptr;
    }
    return xcred;
#else
    return nullptr;
#endif
}

tls_credentials load_tls_credentials_from_memory(
    bool client,
    const std::string &cert,
    const std::string &key) {
#if defined(PUMP_HAVE_TLS)
    SSL_CTX *xcred = nullptr;
    if (client) {
        xcred = SSL_CTX_new(TLS_client_method());
    } else {
        xcred = SSL_CTX_new(TLS_server_method());
    }
    if (xcred == nullptr) {
        return nullptr;
    }

    BIO *cert_bio = BIO_new_mem_buf((void *)cert.c_str(), -1);
    if (cert_bio == nullptr) {
        SSL_CTX_free(xcred);
        return nullptr;
    }

    X509 *x509_cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
    BIO_free(cert_bio);
    if (x509_cert == nullptr) {
        SSL_CTX_free(xcred);
        return nullptr;
    }

    BIO *key_bio = BIO_new_mem_buf((void *)key.c_str(), -1);
    if (key_bio == nullptr) {
        SSL_CTX_free(xcred);
        X509_free(x509_cert);
        return nullptr;
    }
    EVP_PKEY *evp_key = PEM_read_bio_PrivateKey(key_bio, nullptr, 0, nullptr);
    BIO_free(key_bio);
    if (evp_key == nullptr) {
        SSL_CTX_free(xcred);
        X509_free(x509_cert);
        return nullptr;
    }

    if (SSL_CTX_use_certificate(xcred, x509_cert) != 1 ||
        SSL_CTX_use_PrivateKey(xcred, evp_key) != 1) {
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

void delete_tls_credentials(tls_credentials xcred) {
    if (xcred != nullptr) {
#if defined(PUMP_HAVE_TLS)
        SSL_CTX_free((SSL_CTX *)xcred);
#endif
    }
}

tls_session *new_tls_session(
    bool client,
    pump_socket fd,
    tls_credentials xcred) {
#if defined(PUMP_HAVE_TLS)
    tls_session *session = object_create<tls_session>();
    if (session == nullptr) {
        return nullptr;
    }
    SSL *ssl_ctx = SSL_new((SSL_CTX *)xcred);
    if (ssl_ctx == nullptr) {
        object_delete(session);
        return nullptr;
    }
    SSL_set_fd(ssl_ctx, (int32_t)fd);
    if (client) {
        SSL_set_connect_state(ssl_ctx);
    } else {
        SSL_set_accept_state(ssl_ctx);
    }

    session->ssl_ctx = ssl_ctx;

    return session;
#else
    return nullptr;
#endif
}

void delete_tls_session(tls_session *session) {
    if (session == nullptr) {
        return;
    }

    if (session->ssl_ctx != nullptr) {
#if defined(PUMP_HAVE_TLS)
        SSL_free((SSL *)session->ssl_ctx);
#endif
    }
    object_delete(session);
}

int32_t tls_handshake(tls_session *session) {
#if defined(PUMP_HAVE_TLS)
    int32_t ret = SSL_do_handshake((SSL *)session->ssl_ctx);
    int32_t ec = SSL_get_error((SSL *)session->ssl_ctx, ret);
    if (ec != SSL_ERROR_SSL) {
        if (ec == SSL_ERROR_NONE) {
            return tls_handshake_ok;
        } else if (SSL_want_write((SSL *)session->ssl_ctx)) {
            return tls_handshake_send;
        } else if (SSL_want_read((SSL *)session->ssl_ctx)) {
            return tls_handshake_read;
        }
    }
#endif
    // Handshake error
    return tls_handshake_error;
}

bool tls_has_unread_data(tls_session *session) {
#if defined(PUMP_HAVE_TLS)
    if (SSL_has_pending((SSL *)session->ssl_ctx) == 1) {
        return true;
    }
#endif
    return false;
}

int32_t tls_read(
    tls_session *session,
    char *b,
    int32_t size) {
#if defined(PUMP_HAVE_TLS)
    int32_t ret = SSL_read((SSL *)session->ssl_ctx, b, size);
    if (pump_likely(ret > 0)) {
        return ret;
    } else if (SSL_get_error((SSL *)session->ssl_ctx, ret) == SSL_ERROR_WANT_READ) {
        return -1;
    }
#endif
    return 0;
}

int32_t tls_send(
    tls_session *session,
    const char *b,
    int32_t size) {
#if defined(PUMP_HAVE_TLS)
    int32_t ret = SSL_write((SSL *)session->ssl_ctx, b, size);
    if (pump_likely(ret > 0)) {
        return ret;
    } else {
        ret = SSL_get_error((SSL *)session->ssl_ctx, ret);
        if (ret == SSL_ERROR_WANT_WRITE) {
            return -1;
        }
    }
#endif
    return 0;
}

}  // namespace transport
}  // namespace pump