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

#ifndef pump_transport_tls_utils_h
#define pump_transport_tls_utils_h

#include <string>
#include <string.h>

#include "pump/net/socket.h"
#include "pump/toolkit/buffer.h"

namespace pump {
namespace transport {

    const int32_t TLS_HANDSHAKE_OK    = 0;
    const int32_t TLS_HANDSHAKE_READ  = 1;
    const int32_t TLS_HANDSHAKE_SEND  = 2;
    const int32_t TLS_HANDSHAKE_ERROR = 3;

    /*********************************************************************************
     * TLS credentials.
     ********************************************************************************/
    typedef void* tls_credentials;

    /*********************************************************************************
    * TLS session.
    ********************************************************************************/
    struct tls_session {
        void *ssl_ctx;
    };

    /*********************************************************************************
     * Create tls client credentials.
     ********************************************************************************/
    LIB_PUMP tls_credentials create_tls_client_credentials();

    /*********************************************************************************
     * Create tls credentials by file.
     ********************************************************************************/
    LIB_PUMP tls_credentials create_tls_credentials(
        bool client,
        bool by_file,
        const std::string &cert,
        const std::string &key);

    /*********************************************************************************
     * Destory tls certificate.
     ********************************************************************************/
    void destory_tls_credentials(tls_credentials xcred);

    /*********************************************************************************
     * Create tls session
     * This will create ssl context, net read buffer and net send buffer.
     ********************************************************************************/
    tls_session* create_tls_session(
        bool client,
        pump_socket fd,
        tls_credentials xcred);

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

}  // namespace transport
}  // namespace pump

#endif
