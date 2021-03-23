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

// Import "memcpy" function
#include <string.h>

#include "pump/types.h"
#include "pump/toolkit/buffer.h"

namespace pump {
namespace ssl {

    const int32_t TLS_HANDSHAKE_OK = 0;
    const int32_t TLS_HANDSHAKE_READ = 1;
    const int32_t TLS_HANDSHAKE_SEND = 2;
    const int32_t TLS_HANDSHAKE_ERROR = 3;

    struct tls_session {
        // SSL Context
        void_ptr ssl_ctx;
    };
    DEFINE_RAW_POINTER_TYPE(tls_session);

    /*********************************************************************************
     * Create tls session
     * This will create ssl context, net read buffer and net send buffer.
     ********************************************************************************/
    tls_session_ptr create_tls_session(void_ptr xcred, int32_t fd, bool client);

    /*********************************************************************************
     * Destory tls session
     * This will destory ssl context, net read buffer and net send buffer.
     ********************************************************************************/
    void destory_tls_session(tls_session_ptr session);

    /*********************************************************************************
     * Handshake.
     * Return results:
     *     TLS_HANDSHAKE_OK
     *     TLS_HANDSHAKE_READ
     *     TLS_HANDSHAKE_SEND
     *     TLS_HANDSHAKE_ERROR
     ********************************************************************************/
    int32_t tls_handshake(tls_session_ptr session);

    /*********************************************************************************
     * Check has unread data or not
     ********************************************************************************/
    bool tls_has_unread_data(tls_session_ptr session);

    /*********************************************************************************
     * Read
     * If success return read size, else return 0.
     ********************************************************************************/
    int32_t tls_read(tls_session_ptr session, block_t *b, int32_t size);

    /*********************************************************************************
     * Send
     * If success return send size, else return 0.
     ********************************************************************************/
    int32_t tls_send(tls_session_ptr session, const block_t *b, int32_t size);

}  // namespace ssl
}  // namespace pump

#endif
