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

#include "pump/debug.h"
#include "pump/ssl/cert.h"
#include "pump/ssl/ecdhe.h"
#include "pump/protocol/quic/tls/utils.h"
#include "pump/protocol/quic/tls/client_handshaker.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    client_handshaker::client_handshaker()
      : status_(HANDSHAKER_INIT) {
    }

    client_handshaker::~client_handshaker() {
    }

    bool client_handshaker::handshake(config *cfg) {
        if (cfg == nullptr) {
            return false;
        }

        if (status_ != HANDSHAKER_INIT) {
            return false;
        }

        if (!__send_client_hello(cfg)) {
            return false;
        }

        return true;
    }

    bool client_handshaker::handshake(handshake_message *msg) {
        alert_code code = ALERT_NONE;

        switch (msg->type)
        {
        case TLS_MSG_SERVER_HELLO:
            code = __handle_server_hello((server_hello_message*)msg->msg);
            break;
        default:
            code = ALERT_UNEXPECTED_MESSGAE;
            break;
        }

        if (code != ALERT_NONE) {
            // TODO: send alert message.
            return false;
        }

        return true;
    }

    bool client_handshaker::__send_client_hello(config *cfg) {
        if (!cfg->server_name.empty()) {
            return false;
        }

        if (cfg->alpn.empty() || cfg->alpn.size() > 255) {
            return false;
        }

        hello_.legacy_version = TLS_VSERVER_12;

        std::default_random_engine random;
        for (int32_t i = 0; i < (int32_t)sizeof(hello_.random); i++) {
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
        hello_.supported_groups.push_back(TLS_CURVE_X25519);
        hello_.supported_groups.push_back(TLS_CURVE_P256);
        hello_.supported_groups.push_back(TLS_CURVE_P384);
        hello_.supported_groups.push_back(TLS_CURVE_P521);

        hello_.supported_points.clear();
        hello_.supported_points.push_back(TLS_POINT_FORMAT_UNCOMPRESSED);

        // Not support session ticket.
        hello_.is_support_session_ticket = false;
        hello_.session_ticket.clear();

        // Just support tls 13 signature algorithms.
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
            session_.keys = ssl::create_ecdhe_parameter(TLS_CURVE_X25519);
            if (session_.keys == nullptr) {
                return false;
            }
            key_share ks;
            ks.group = TLS_CURVE_X25519;
            ks.data = ssl::get_ecdhe_pubkey(session_.keys);
            hello_.key_shares.push_back(std::move(ks));
        }

        // Not support eraly data.
        hello_.is_support_early_data = false;

        hello_.psk_modes.clear();
        hello_.psk_identities.clear();
        hello_.psk_binders.clear();

        uint8_t buf[4096];
        int32_t size = pack_client_hello(&hello_, buf, sizeof(buf));
        if (size < 0) {
            return false;
        }
        
        // TODO: send client hello message.

        
        status_ = HANDSHAKER_CLIENT_HELLO_SENT;

        return true;
    }

    alert_code client_handshaker::__handle_server_hello(server_hello_message *msg) {
        if (status_ != HANDSHAKER_CLIENT_HELLO_SENT &&
            status_ != HANDSHAKER_RETRY_HELLO_SENT) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        if (msg->legacy_version != TLS_VSERVER_12) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (msg->supported_version != TLS_VSERVER_13) {
            return ALERT_PROTOCOL_VERSION;
        }

        if (msg->is_support_ocsp_stapling || 
            msg->is_support_session_ticket || 
            msg->is_support_renegotiation_info || 
            !msg->renegotiation_info.empty() || 
            !msg->alpn.empty() || 
            !msg->scts.empty()) {
            return ALERT_UNSUPPORTED_EXTENSION;
        }

        if (hello_.session_id != msg->session_id) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (msg->compression_method != TLS_COMPRESSION_METHOD_NONE) {
            return ALERT_ILLEGAL_PARAMETER; 
        }

        if (!is_contains(hello_.cipher_suites, msg->cipher_suite) ||
            !load_tls13_cipher_suite_params(msg->cipher_suite, &session_.suite_params)) {
            return ALERT_ILLEGAL_PARAMETER;
        }
        transcript_ = ssl::create_hash_context(session_.suite_params.algo);

        uint8_t buffer[4096];
        int32_t size = pack_client_hello(&hello_, buffer, sizeof(buffer));
        PUMP_DEBUG_CHECK(ssl::update_hash(transcript_, buffer, size));

        if (memcmp(msg->random, hello_retry_request_random, 32) == 0) {
            if (status_ == HANDSHAKER_RETRY_HELLO_SENT) {
                return ALERT_UNEXPECTED_MESSGAE;
            }
            return __send_retry_hello(msg);
        }

        size = pack_server_hello(msg, buffer, sizeof(buffer));
        PUMP_DEBUG_CHECK(ssl::update_hash(transcript_, buffer, size));

        if (!msg->cookie.empty()) {
            return ALERT_UNSUPPORTED_EXTENSION;
        }

        if (msg->selected_group != TLS_CURVE_UNKNOWN) {
            return ALERT_DECODE_ERROR;
        }

        if (msg->selected_key_share.group == TLS_CURVE_UNKNOWN || 
            msg->selected_key_share.group != hello_.key_shares[0].group) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (msg->has_selected_psk_identity) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        std::string shared_key = ssl::gen_ecdhe_shared_key(session_.keys, msg->selected_key_share.data);
        if (shared_key.empty()) {
            return ALERT_ILLEGAL_PARAMETER; 
        }

        std::string handshake_secret;
        {
            std::string secret = cipher_suite_device_secret(
                                    &session_.suite_params, 
                                    cipher_suite_extract(&session_.suite_params, "", ""),
                                    "derived", 
                                    nullptr);
            handshake_secret = cipher_suite_extract(&session_.suite_params, secret, shared_key);
        }

        session_.client_secret = cipher_suite_device_secret(
                                    &session_.suite_params, 
                                    handshake_secret,
                                    client_handshake_traffic_label, 
                                    transcript_);

        session_.server_secret = cipher_suite_device_secret(
                                    &session_.suite_params, 
                                    handshake_secret,
                                    server_handshake_traffic_label, 
                                    transcript_);

        {
            std::string secret = cipher_suite_device_secret(
                                    &session_.suite_params, 
                                    handshake_secret, 
                                    "derived", 
                                    nullptr);
            session_.master_secret = cipher_suite_extract(&session_.suite_params, secret, "");
        }
        
        status_ = HANDSHAKER_SERVER_HELLO_RECV;

        return true;
    }

    alert_code client_handshaker::__send_retry_hello(server_hello_message *msg) {
        if (status_ != HANDSHAKER_CLIENT_HELLO_SENT) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        std::string hash;
        if (!ssl::sum_hash(transcript_, hash)) {
            return ALERT_INTERNAL_ERROR;
        }
        ssl::reset_hash_context(transcript_);

        std::string hash_msg;
        hash_msg.push_back(TLS_MSG_MESSAGE_HASH);
        hash_msg.append(2, 0);
        hash_msg.push_back((int8_t)hash.size());
        hash_msg.append(hash);

        uint8_t msg_buffer[4096];
        int32_t size = pack_server_hello(msg, msg_buffer, 4096);
        hash_msg.append((char*)msg_buffer, (size_t)size);

        ssl::update_hash(transcript_, hash_msg);

        if (msg->selected_group == TLS_CURVE_UNKNOWN && msg->cookie.empty()) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (!msg->cookie.empty()) {
            hello_.cookie = msg->cookie;
        }

        if (msg->selected_key_share.group != TLS_CURVE_UNKNOWN) {
            return ALERT_DECODE_ERROR;
        }

        return ALERT_NONE;
    }

    alert_code client_handshaker::__handle_encrypted_extensions(encrypted_extensions_message *msg) {
        if (status_ != HANDSHAKER_SERVER_HELLO_RECV) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        if (!msg->alpn.empty()) {
            if (hello_.alpns.empty() || !is_contains(hello_.alpns, msg->alpn)) {
                return ALERT_UNSUPPORTED_EXTENSION; 
            }
            session_.alpn = msg->alpn;
        }

        if (hello_.is_support_early_data && msg->is_support_early_data) {
            session_.enable_zero_rtt = true;
        }

        status_ = HANDSHAKER_ENCRYPTED_EXTENSIONS_RECV;

        return ALERT_NONE;
    }

    alert_code client_handshaker::__handle_certificate_request_tls13(certificate_request_tls13_message *msg) {
        if (status_ != HANDSHAKER_ENCRYPTED_EXTENSIONS_RECV) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        certificate_request_ = *msg;

        status_ = HANDSHAKER_CARTIFICATE_REQUEST_RECV;

        return ALERT_NONE;
    }

    alert_code client_handshaker::__handle_certificate_tls13(certificate_tls13_message *msg) {
        if (status_ != HANDSHAKER_ENCRYPTED_EXTENSIONS_RECV &&
            status_ != HANDSHAKER_CARTIFICATE_REQUEST_RECV) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        if (msg->certificates.empty()) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (!certificate_load(msg->certificates, session_.certs)) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (!ssl::x509_certificate_verify(session_.certs)) {
            return ALERT_BAD_CERTIFICATE;
        }

        session_.scts = msg->scts;
     
        session_.ocsp_staple = msg->ocsp_staple;

        status_ = HANDSHAKER_CARTIFICATE_RECV;

        return ALERT_NONE;
    }

    alert_code client_handshaker::__handle_certificate_verify(certificate_verify_message *msg) {
        if (status_ != HANDSHAKER_CARTIFICATE_RECV) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        if (!is_contains(hello_.supported_signature_algorithms, msg->signature_algorithm)) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        return ALERT_NONE;
    }

}
}
}
}