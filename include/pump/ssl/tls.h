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

#ifndef pump_ssl_tls_h
#define pump_ssl_tls_h

#include <string>
#include <string.h>

#include "pump/types.h"
#include "pump/toolkit/buffer.h"

namespace pump {
namespace ssl {

    const int32_t TLS_HANDSHAKE_OK    = 0;
    const int32_t TLS_HANDSHAKE_READ  = 1;
    const int32_t TLS_HANDSHAKE_SEND  = 2;
    const int32_t TLS_HANDSHAKE_ERROR = 3;

    /*********************************************************************************
     * Create tls client certificate.
     ********************************************************************************/
    LIB_PUMP void* create_tls_client_certificate();

    /*********************************************************************************
     * Create tls certificate by file.
     ********************************************************************************/
    LIB_PUMP void* create_tls_certificate_by_file(
        bool client,
        const std::string &cert,
        const std::string &key);

    /*********************************************************************************
     * Create tls certificate by buffer.
     ********************************************************************************/
    LIB_PUMP void* create_tls_certificate_by_buffer(
        bool client,
        const std::string &cert,
        const std::string &key);

    /*********************************************************************************
     * Destory tls certificate.
     ********************************************************************************/
    void destory_tls_certificate(void *xcred);

    struct tls_session {
        void *ssl_ctx;
    };

    /*********************************************************************************
     * Create tls session
     * This will create ssl context, net read buffer and net send buffer.
     ********************************************************************************/
    tls_session* create_tls_session(
        void *xcred, 
        int32_t fd, 
        bool client);

    /*********************************************************************************
     * Destory tls session
     * This will destory ssl context, net read buffer and net send buffer.
     ********************************************************************************/
    void destory_tls_session(tls_session *session);

    /*********************************************************************************
     * Handshake.
     * Return results:
     *     TLS_HANDSHAKE_OK
     *     TLS_HANDSHAKE_READ
     *     TLS_HANDSHAKE_SEND
     *     TLS_HANDSHAKE_ERROR
     ********************************************************************************/
    int32_t tls_handshake(tls_session *session);

    /*********************************************************************************
     * Check has unread data or not
     ********************************************************************************/
    bool tls_has_unread_data(tls_session *session);

    /*********************************************************************************
     * Read
     * If success return read size, else return 0.
     ********************************************************************************/
    int32_t tls_read(
        tls_session *session, 
        block_t *b, 
        int32_t size);

    /*********************************************************************************
     * Send
     * If success return send size, else return 0.
     ********************************************************************************/
    int32_t tls_send(
        tls_session *session, 
        const block_t *b, 
        int32_t size);

}  // namespace ssl
}  // namespace pump

#endif
