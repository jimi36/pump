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

#include <random>

#include "pump/protocol/quic/tls/client_handshaker.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    client_handshaker::client_handshaker() {
    }

    client_handshaker::~client_handshaker() {
    }

    bool client_handshaker::handshake(config *cfg) {
        if (cfg == nullptr) {
            return false;
        }

        if (__init_client_hello(cfg)) {
            return false;
        }

        uint8_t buf[4096];
        int32_t size = pack_client_hello(&hello_, buf, sizeof(buf));
        if (size < 0) {
            return false;
        }
        
        // TODO: send client hello message.

        return true;
    }

    bool client_handshaker::handshake(handshake_message *msg) {

    }

    bool client_handshaker::__init_client_hello(config *cfg) {
        if (!cfg->server_name.empty()) {
            return false;
        }

        if (cfg->alpn.empty() || cfg->alpn.size() > 255) {
            return false;
        }

        hello_.legacy_version = TLS_VSERVER_12;

        std::default_random_engine random;
        for (int32_t i = 0; i < sizeof(hello_.random); i++) {
            hello_.random[i]= random();
        }

        // No session id.
        hello_.session_id.clear();

        // Just include tls 1.3 cipher suites.
        hello_.cipher_suites.clear();
        hello_.cipher_suites.push_back(TLS_AES_128_GCM_SHA256);
        hello_.cipher_suites.push_back(TLS_CHACHA20_POLY1305_SHA256);
        hello_.cipher_suites.push_back(TLS_AES_256_GCM_SHA384);

        hello_.compression_methods.clear();
        hello_.compression_methods.push_back(TLS_COMPRESSION_METHOD_NONE);

        hello_.server_name = cfg->server_name;

        hello_.is_support_ocsp_stapling = true;

        hello_.supported_groups.clear();
        hello_.supported_groups.push_back(TLS_GROUP_X25519);
        hello_.supported_groups.push_back(TLS_GROUP_P256);
        hello_.supported_groups.push_back(TLS_GROUP_P384);
        hello_.supported_groups.push_back(TLS_GROUP_P2521);

        hello_.supported_points.clear();
        hello_.supported_points.push_back(TLS_POINT_FORMAT_UNCOMPRESSED);

        hello_.is_support_session_ticket = false;
        hello_.session_ticket.clear();

        // Just include tls 13 signature algorithms.
        hello_.supported_signature_algorithms.clear();
        //hello_.supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_PSSWITHSHA256);
        hello_.supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_ECDSAWITHP256AndSHA256);
        //hello_.supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_ED25519);
        //hello_.supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_PSSWITHSHA384);
        //hello_.supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_PSSWITHSHA512);
        //hello_.supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_PKCS1WITHSHA256);
        //hello_.supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_PKCS1WITHSHA384);
        //hello_.supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_PKCS1WITHSHA512);
        hello_.supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_ECDSAWITHP384AndSHA384);
        hello_.supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_ECDSAWITHP521AndSHA512);
        //hello_.supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_PKCS1WITHSHA1);
        //hello_.supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_ECDSAWITHSHA1);

        hello_.supported_signature_algorithms_certs.clear();

        hello_.is_support_renegotiation_info = true;
        hello_.renegotiation_info.clear();

        hello_.alpns.push_back(cfg->alpn);

        hello_.is_support_scts = true;

        // Just support tls 13.
        hello_.supported_versions.clear();
        hello_.supported_versions.push_back(TLS_VSERVER_13);

        hello_.cookie.clear();

        hello_.key_shares.clear();
        if (hello_.supported_versions[0] == TLS_VSERVER_13) {
            if (!ssl::generate_X25519_key_pair(&ecdhe_keys_)) {
                return false;
            }
            key_share ks;
            ks.group = TLS_GROUP_X25519;
            ks.data = ecdhe_keys_.pubkey;
            hello_.key_shares.push_back(std::move(ks));
        }

        hello_.is_support_early_data = false;

        hello_.psk_modes.clear();
        hello_.psk_identities.clear();
        hello_.psk_binders.clear();

        return true;
    }

}
}
}
}