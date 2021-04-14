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
#include "pump/protocol/quic/tls/types.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    void init_connection_session(connection_session_ptr session) {
        session->version = TLS_VERSION_UNKNOWN;
        session->cipher_suite_ctx = nullptr;
        session->ecdhe_ctx = nullptr;
        session->enable_zero_rtt = false;
    }

    void reset_connection_session(connection_session_ptr session) {
        session->version = TLS_VERSION_UNKNOWN;

        if (session->cipher_suite_ctx) {
            object_delete(session->cipher_suite_ctx);
            session->cipher_suite_ctx = nullptr;
        }

        if (session->ecdhe_ctx) {
            ssl::delete_ecdhe_context(session->ecdhe_ctx);
            session->ecdhe_ctx = nullptr;
        }

        session->enable_zero_rtt = false;

        session->server_name.clear();

        session->alpn.clear();

        session->ocsp_staple.clear();

        session->scts.clear();

        session->master_secret.clear();
        session->client_secret.clear();
        session->server_secret.clear();
        session->traffic_secret.clear();
        session->handshake_secret.clear();
        session->export_master_secret.clear();

        for (auto cert : session->certs) {
            ssl::free_x509_certificate(cert);
        }
        session->certs.clear();

        for (auto cert : session->peer_certs) {
            ssl::free_x509_certificate(cert);
        }
        session->peer_certs.clear();
    }

}
}
}
}