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

#ifndef pump_ssl_tls_helper_h
#define pump_ssl_tls_helper_h

// Import "memcpy" function
#include <string.h>

#include "pump/types.h"
#include "pump/toolkit/buffer.h"

namespace pump {
namespace ssl {

    struct tls_session {
        // SSL Context
        void_ptr ssl_ctx;

#if defined(PUMP_HAVE_OPENSSL)
        void_ptr read_bio;
        void_ptr send_bio;
#endif
        // Net read buffer
        int32_t net_read_data_pos;
        int32_t net_read_data_size;
        toolkit::io_buffer_ptr net_read_iob;

        // Net send buffer
        toolkit::io_buffer_ptr net_send_iob;

        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        tls_session()
            : ssl_ctx(nullptr),
#if defined(PUMP_HAVE_OPENSSL)
              read_bio(nullptr),
              send_bio(nullptr),
#endif
              net_read_data_pos(0),
              net_read_data_size(0),
              net_read_iob(nullptr),
              net_send_iob(nullptr) {
        }

#if defined(PUMP_HAVE_GNUTLS)
        /*********************************************************************************
         * Read from net read buffer.
         ********************************************************************************/
        uint32 read_from_net_read_buffer(block_ptr b, int32 maxlen) {
            // Get max size to read.
            int32 size = net_read_data_size > maxlen ? maxlen : net_read_data_size;
            if (size > 0) {
                // Copy read data to buffer.
                memcpy(b, net_read_iob->buffer() + net_read_data_pos, size);
                net_read_data_size -= size;
                net_read_data_pos += size;
            }
            return size;
        }

        /*********************************************************************************
         * Send to net send buffer
         ********************************************************************************/
        void send_to_net_send_buffer(c_block_ptr b, int32 size) {
            net_send_iob->append(b, size);
        }
#endif
    };
    DEFINE_RAW_POINTER_TYPE(tls_session);

    /*********************************************************************************
     * Create tls session
     * This will create ssl context, net read buffer and net send buffer.
     ********************************************************************************/
    tls_session_ptr create_tls_session(void_ptr xcred, bool client, int32_t buffer_size);

    /*********************************************************************************
     * Destory tls session
     * This will destory ssl context, net read buffer and net send buffer.
     ********************************************************************************/
    void destory_tls_session(tls_session_ptr session);

    /*********************************************************************************
     * TLS handshake.
     * If handshading complete return 0.
     * If handshading incomplete return 1.
     * If handshaking error return -1.
     ********************************************************************************/
    int32_t tls_handshake(tls_session_ptr session);

    /*********************************************************************************
     * TLS read
     * If success return read size, else return 0.
     ********************************************************************************/
    int32_t tls_read(tls_session_ptr session, block_t *b, int32_t size);

    /*********************************************************************************
     * TLS send
     * If success return send size, else return 0.
     ********************************************************************************/
    int32_t tls_send(tls_session_ptr session, const block_t *b, int32_t size);

}  // namespace ssl
}  // namespace pump

#endif
