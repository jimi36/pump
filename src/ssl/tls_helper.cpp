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
#include "pump/ssl/tls_helper.h"

#if defined(PUMP_HAVE_OPENSSL)
extern "C" {
#include <openssl/ssl.h>
}
#endif

#if defined(PUMP_HAVE_GNUTLS)
extern "C" {
#include <gnutls/gnutls.h>
}
#endif

namespace pump {
namespace ssl {

    tls_session_ptr create_tls_session(void_ptr xcred, int32_t fd, bool client) {
#if defined(PUMP_HAVE_GNUTLS)
        tls_session_ptr session = object_create<tls_session>();
        gnutls_session_t ssl_ctx = nullptr;
        if (client) {
            gnutls_init(&ssl_ctx, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
        } else {
            gnutls_init(&ssl_ctx, GNUTLS_SERVER | GNUTLS_NONBLOCK);
        }
        gnutls_set_default_priority(ssl_ctx);
        // Set GnuTLS session with credentials
        gnutls_credentials_set(ssl_ctx, GNUTLS_CRD_CERTIFICATE, xcred);
        // Set GnuTLS handshake timeout time.
        gnutls_handshake_set_timeout(ssl_ctx, GNUTLS_INDEFINITE_TIMEOUT);
        // Set GnuTLS transport fd.
        gnutls_transport_set_int(ssl_ctx, fd);

        session->ssl_ctx = ssl_ctx;

        return session;
#elif defined(PUMP_HAVE_OPENSSL)
        tls_session_ptr session = object_create<tls_session>();
        SSL *ssl_ctx = SSL_new((SSL_CTX*)xcred);
        SSL_set_fd(ssl_ctx, fd);
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

    void destory_tls_session(tls_session_ptr session) {
        if (!session) {
            return;
        }

#if defined(PUMP_HAVE_GNUTLS)
        if (session->ssl_ctx) {
            gnutls_deinit((gnutls_session_t)session->ssl_ctx);
        }
#elif defined(PUMP_HAVE_OPENSSL)
        if (session->ssl_ctx) {
            SSL_free((SSL*)session->ssl_ctx);
        }
#endif
        object_delete(session);
    }

    int32_t tls_handshake(tls_session_ptr session) {
#if defined(PUMP_HAVE_GNUTLS)
        int32_t ret = gnutls_handshake((gnutls_session_t)session->ssl_ctx);
        if (ret == 0) {
            return TLS_HANDSHAKE_OK;
        } else if (gnutls_error_is_fatal(ret) == 0) {
            if (gnutls_record_get_direction((gnutls_session_t)session->ssl_ctx) == 0) {
                return TLS_HANDSHAKE_READ;
            } else {
                return TLS_HANDSHAKE_SEND;
            }
        }
#elif defined(PUMP_HAVE_OPENSSL)
        int32_t ret = SSL_do_handshake((SSL*)session->ssl_ctx);
        int32_t ec = SSL_get_error((SSL*)session->ssl_ctx, ret);
        if (ec != SSL_ERROR_SSL) {
            if (ec == SSL_ERROR_NONE) {
                return TLS_HANDSHAKE_OK;
            }
            if (SSL_want_write((SSL*)session->ssl_ctx)) {
                return TLS_HANDSHAKE_SEND;
            } else if (SSL_want_read((SSL*)session->ssl_ctx)) {
                return TLS_HANDSHAKE_READ;
            }
        }
#endif
        // Handshake error
        return TLS_HANDSHAKE_ERROR;
    }

    bool tls_has_unread_data(tls_session_ptr session) {
#if defined(PUMP_HAVE_GNUTLS)
        if (gnutls_record_check_pending((gnutls_session_t)session->ssl_ctx) > 0) {
            return true;
        }
#elif defined(PUMP_HAVE_OPENSSL)
        if (SSL_pending((SSL*)session->ssl_ctx) == 1) {
            return true;
        }
#endif
        return false;
    }

    int32_t tls_read(tls_session_ptr session, block_t *b, int32_t size) {
#if defined(PUMP_HAVE_GNUTLS)
        int32_t ret = (int32_t)gnutls_read((gnutls_session_t)session->ssl_ctx, b, size);
        if (PUMP_LIKELY(ret > 0)) {
            return ret;
        } else if (ret == GNUTLS_E_AGAIN) {
            return -1;
        }
#elif defined(PUMP_HAVE_OPENSSL)
        int32_t ret = SSL_read((SSL*)session->ssl_ctx, b, size);
        if (PUMP_LIKELY(ret > 0)) {
            return ret;
        } else if (SSL_get_error((SSL*)session->ssl_ctx, ret) == SSL_ERROR_WANT_READ) {
            return -1;
        }
#endif
        return 0;
    }

    int32_t tls_send(tls_session_ptr session, const block_t *b, int32_t size) {
#if defined(PUMP_HAVE_GNUTLS)
        return (int32_t)gnutls_write((gnutls_session_t)session->ssl_ctx, b, size);
#elif defined(PUMP_HAVE_OPENSSL)
        int32_t ret = SSL_write((SSL*)session->ssl_ctx, b, size);
        if (PUMP_LIKELY(ret > 0)) {
            return ret;
        } else if (SSL_get_error((SSL*)session->ssl_ctx, ret) == SSL_ERROR_WANT_WRITE) {
            return -1;
        }
#endif
        return 0;
    }

}  // namespace ssl
}  // namespace pump