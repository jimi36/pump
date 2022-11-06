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

#include <pump/net/socket.h>
#include <pump/transport/types.h>

namespace pump {
namespace transport {

/*********************************************************************************
 * TLS credentials.
 ********************************************************************************/
typedef void *tls_credentials;

/*********************************************************************************
 * TLS session.
 ********************************************************************************/
struct tls_session {
    void *ssl_ctx;
};

/*********************************************************************************
 * New tls client credentials.
 ********************************************************************************/
tls_credentials new_client_tls_credentials();

/*********************************************************************************
 * Load tls credentials.
 ********************************************************************************/
tls_credentials load_tls_credentials_from_file(
    bool client,
    const std::string &cert,
    const std::string &key);
tls_credentials load_tls_credentials_from_memory(
    bool client,
    const std::string &cert,
    const std::string &key);

/*********************************************************************************
 * Delete tls certificate.
 ********************************************************************************/
void delete_tls_credentials(tls_credentials xcred);

/*********************************************************************************
 * New tls session
 * This will new ssl context, net read buffer and net send buffer.
 ********************************************************************************/
tls_session *new_tls_session(
    bool client,
    pump_socket fd,
    tls_credentials xcred);

/*********************************************************************************
 * Delete tls session
 * This will delete ssl context, net read buffer and net send buffer.
 ********************************************************************************/
void delete_tls_session(tls_session *session);

/*********************************************************************************
 * Handshake.
 ********************************************************************************/
tls_handshake_phase tls_handshake(tls_session *session);

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
    char *b,
    int32_t size);

/*********************************************************************************
 * Send
 * If success return send size, else return 0.
 ********************************************************************************/
int32_t tls_send(
    tls_session *session,
    const char *b,
    int32_t size);

}  // namespace transport
}  // namespace pump

#endif
