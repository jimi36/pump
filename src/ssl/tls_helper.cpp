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

#if defined(PUMP_HAVE_GNUTLS)
    class tls_net_layer {
      public:
        PUMP_INLINE static ssize_t data_pull(gnutls_transport_ptr_t ptr,
                                             void_ptr data,
                                             size_t maxlen) {
            tls_session_ptr s = (tls_session_ptr)ptr;
            int32_t size = s->read_from_net_read_buffer((block_t*)data, (int32_t)maxlen);
            if (size == 0) {
                return -1;
            }

            return size;
        }

        PUMP_INLINE static ssize_t data_push(gnutls_transport_ptr_t ptr,
                                             c_void_ptr data,
                                             size_t len) {
            tls_session_ptr(ptr)->send_to_net_send_buffer((const block_t*)data, (int32_t)len);
            return len;
        }

        PUMP_INLINE static int get_error(gnutls_transport_ptr_t ptr) {
            return EAGAIN;
        }
    };
#endif

    bool tls_session::has_data_pending() {
        if (net_read_data_size > 0) {
            return true;
        }
#if defined(PUMP_HAVE_GNUTLS)
        if (gnutls_record_check_pending((gnutls_session_t)ssl_ctx) == 1) {
            return true;
        }
#elif defined(PUMP_HAVE_OPENSSL)
        if (SSL_pending((SSL*)ssl_ctx) == 1) {
            return true;
        }
#endif
        return false;
    }

    tls_session_ptr create_tls_session(
        void_ptr xcred, 
        bool client, 
        int32_t buffer_size) {
#if defined(PUMP_HAVE_GNUTLS)
        tls_session_ptr session = object_create<tls_session>();
        gnutls_session_t ssl_ctx = nullptr;
        if (client) {
            gnutls_init(&ssl_ctx, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
        } else {
            gnutls_init(&ssl_ctx, GNUTLS_SERVER | GNUTLS_NONBLOCK);
        }
        gnutls_set_default_priority(ssl_ctx);
        // Set transport ptr
        gnutls_transport_set_ptr(ssl_ctx, session);
        // Set GnuTLS session with credentials
        gnutls_credentials_set(ssl_ctx, GNUTLS_CRD_CERTIFICATE, xcred);
        // Set GnuTLS handshake timeout time 1000ms.
        // gnutls_handshake_set_timeout(ssl_ctx, 1000);
        gnutls_handshake_set_timeout(ssl_ctx, GNUTLS_INDEFINITE_TIMEOUT);
        // Set callback that allows GnuTLS to PUSH data TO the transport layer
        gnutls_transport_set_push_function(ssl_ctx, tls_net_layer::data_push);
        // Set callback that allows GnuTls to PULL data FROM the tranport layer
        gnutls_transport_set_pull_function(ssl_ctx, tls_net_layer::data_pull);
        // Set callback that allows GnuTls to Get error for PULL or PUSH
        gnutls_transport_set_errno_function(ssl_ctx, tls_net_layer::get_error);

        session->ssl_ctx = ssl_ctx;
        session->net_send_iob = toolkit::io_buffer::create();
        session->net_read_iob = toolkit::io_buffer::create();
        session->net_read_iob->init_with_size(buffer_size);

        return session;
#elif defined(PUMP_HAVE_OPENSSL)
        tls_session_ptr session = object_create<tls_session>();
        SSL *ssl_ctx = SSL_new((SSL_CTX*)xcred);
        BIO *rbio = BIO_new(BIO_s_mem());
        BIO *sbio = BIO_new(BIO_s_mem());

        SSL_set_bio(ssl_ctx, rbio, sbio);
        if (client) {
            SSL_set_connect_state(ssl_ctx);
        } else {
            SSL_set_accept_state(ssl_ctx);
        }

        session->ssl_ctx = ssl_ctx;
        session->net_send_iob = toolkit::io_buffer::create();
        session->net_read_iob = toolkit::io_buffer::create();
        session->net_read_iob->init_with_size(buffer_size);
        session->read_bio = rbio;
        session->send_bio = sbio;

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
        if (session->net_read_iob) {
            session->net_read_iob->sub_ref();
        }
        if (session->net_send_iob) {
            session->net_send_iob->sub_ref();
        }
        object_delete(session);
    }

    int32_t tls_handshake(tls_session_ptr session) {
#if defined(PUMP_HAVE_GNUTLS)
        int32_t ret = gnutls_handshake((gnutls_session_t)session->ssl_ctx);
        if (ret == 0) {
            // Handshake compelte.
            return 0;
        } else if (gnutls_error_is_fatal(ret) == 0) {
            // Handshake incompelte.
            return 1;
        }
#elif defined(PUMP_HAVE_OPENSSL)
        if (session->net_read_data_size > 0) {
            int32_t bio_size = BIO_write((BIO*)session->read_bio,
                                         session->net_read_iob->buffer() + session->net_read_data_pos,
                                         session->net_read_data_size);
            PUMP_ASSERT(bio_size == session->net_read_data_size);
            session->net_read_data_size -= bio_size;
            session->net_read_data_pos = 0;
        }

        int32_t ret = SSL_do_handshake((SSL*)session->ssl_ctx);
        int32_t ec = SSL_get_error((SSL*)session->ssl_ctx, ret);
        if (ec != SSL_ERROR_SSL) {
            BUF_MEM *bptr = nullptr;
            PUMP_DEBUG_CHECK(BIO_get_mem_ptr((BIO*)session->send_bio, &bptr));
            if (bptr->length > 0) {
                PUMP_DEBUG_CHECK(session->net_send_iob->append(bptr->data, (uint32_t)bptr->length));
            }
            BIO_read((BIO*)session->send_bio, bptr->data, (int32_t)bptr->length);
            if (ec == SSL_ERROR_NONE) {
                // Handshake compelte.
                return 0;
            }
            // Handshake incompelte.
            return 1;
        }
#endif
        // Handshake error
        return -1;
    }

    int32_t tls_read(tls_session_ptr session, block_t *b, int32_t size) {
#if defined(PUMP_HAVE_GNUTLS)
        int32_t ret = (int32_t)gnutls_read((gnutls_session_t)session->ssl_ctx, b, size);
        if (ret > 0) {
            return ret;
        } else if (ret == GNUTLS_E_AGAIN) {
            return -1;
        }
#elif defined(PUMP_HAVE_OPENSSL)
        if (session->net_read_data_size == 0) {
            return -1;
        }

        int32_t bio_size = BIO_write((BIO*)session->read_bio,
                                     session->net_read_iob->buffer(),
                                     session->net_read_data_size);
        PUMP_ASSERT(bio_size == session->net_read_data_size);
        session->net_read_data_size -= bio_size;
        session->net_read_data_pos = 0;

        int32_t ret = SSL_read((SSL*)session->ssl_ctx, b, size);
        if (PUMP_LIKELY(ret > 0)) {
            return ret;
        }

        if (PUMP_LIKELY(SSL_get_error((SSL*)session->ssl_ctx, ret) != SSL_ERROR_SSL)) {
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
            BUF_MEM *bptr = nullptr;
            PUMP_DEBUG_CHECK(BIO_get_mem_ptr((BIO*)session->send_bio, &bptr));
            PUMP_DEBUG_CHECK(session->net_send_iob->append(bptr->data, (uint32_t)bptr->length));
            BIO_read((BIO*)session->send_bio, bptr->data, (int32_t)bptr->length);
            return ret;
        }

        if (PUMP_LIKELY(SSL_get_error((SSL*)session->ssl_ctx, ret) != SSL_ERROR_SSL)) {
            return -1;
        }
#endif
        return 0;
    }

}  // namespace ssl
}  // namespace pump