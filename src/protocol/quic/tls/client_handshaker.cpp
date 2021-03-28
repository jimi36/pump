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
            code = __handle_server_hello(msg);
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

        client_hello_.type = TLS_MSG_CLIENT_HELLO;
        PUMP_DEBUG_CHECK(init_handshake_message(&client_hello_));
        client_hello_message *hello = (client_hello_message*)client_hello_.msg;

        hello->legacy_version = TLS_VSERVER_12;

        std::default_random_engine random;
        for (int32_t i = 0; i < (int32_t)sizeof(hello->random); i++) {
            hello->random[i]= random();
        }

        // No session id.
        hello->session_id.clear();

        // Just include tls 1.3 cipher suites.
        hello->cipher_suites.clear();
        hello->cipher_suites.push_back(TLS_AES_128_GCM_SHA256);
        hello->cipher_suites.push_back(TLS_CHACHA20_POLY1305_SHA256);
        hello->cipher_suites.push_back(TLS_AES_256_GCM_SHA384);

        hello->compression_methods.clear();
        hello->compression_methods.push_back(TLS_COMPRESSION_METHOD_NONE);

        hello->server_name = cfg->server_name;

        hello->is_support_ocsp_stapling = true;

        hello->supported_groups.clear();
        hello->supported_groups.push_back(TLS_CURVE_X25519);
        hello->supported_groups.push_back(TLS_CURVE_P256);
        hello->supported_groups.push_back(TLS_CURVE_P384);
        hello->supported_groups.push_back(TLS_CURVE_P521);

        hello->supported_points.clear();
        hello->supported_points.push_back(TLS_POINT_FORMAT_UNCOMPRESSED);

        // Not support session ticket.
        hello->is_support_session_ticket = false;
        hello->session_ticket.clear();

        // Just support tls 13 signature algorithms.
        hello->supported_signature_algorithms.clear();
        //hello->supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_PSSWITHSHA256);
        hello->supported_signature_algorithms.push_back(TLS_SIGN_ECDSAWITHP256AndSHA256);
        //hello->supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_ED25519);
        //hello->supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_PSSWITHSHA384);
        //hello->supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_PSSWITHSHA512);
        //hello->supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_PKCS1WITHSHA256);
        //hello->supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_PKCS1WITHSHA384);
        //hello->supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_PKCS1WITHSHA512);
        hello->supported_signature_algorithms.push_back(TLS_SIGN_ECDSAWITHP384AndSHA384);
        hello->supported_signature_algorithms.push_back(TLS_SIGN_ECDSAWITHP521AndSHA512);
        //hello->supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_PKCS1WITHSHA1);
        //hello->supported_signature_algorithms.push_back(TLS_SIGN_SCHEME_ECDSAWITHSHA1);

        hello->supported_signature_algorithms_certs.clear();

        hello->is_support_renegotiation_info = true;
        hello->renegotiation_info.clear();

        hello->alpns.push_back(cfg->alpn);

        hello->is_support_scts = true;

        // Just support tls 13.
        hello->supported_versions.clear();
        hello->supported_versions.push_back(TLS_VSERVER_13);

        hello->cookie.clear();

        hello->key_shares.clear();
        if (hello->supported_versions[0] == TLS_VSERVER_13) {
            session_.ecdhe_param = ssl::create_ecdhe_parameter(TLS_CURVE_X25519);
            if (session_.ecdhe_param == nullptr) {
                return false;
            }
            key_share ks;
            ks.group = TLS_CURVE_X25519;
            ks.data = ssl::get_ecdhe_pubkey(session_.ecdhe_param);
            hello->key_shares.push_back(std::move(ks));
        }

        // Not support eraly data.
        hello->is_support_early_data = false;

        hello->psk_modes.clear();
        hello->psk_identities.clear();
        hello->psk_binders.clear();

        const std::string& buffer = pack_handshake_message(&client_hello_);
        if (buffer.empty()) {
            return false;
        }        
        // TODO: send client hello message.
        
        status_ = HANDSHAKER_CLIENT_HELLO_SENT;

        return true;
    }

    alert_code client_handshaker::__handle_server_hello(handshake_message *msg) {
        if (status_ != HANDSHAKER_CLIENT_HELLO_SENT &&
            status_ != HANDSHAKER_RETRY_HELLO_SENT) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        server_hello_message *server_hello = (server_hello_message*)msg->msg;
        PUMP_ASSERT(server_hello);

        client_hello_message *client_hello = (client_hello_message*)client_hello_.msg;
        PUMP_ASSERT(client_hello);

        if (memcmp(server_hello->random + 24, DOWNGRRADE_CANARY_TLS11, 8) == 0 || 
            memcmp(server_hello->random + 24, DOWNGRRADE_CANARY_TLS12, 8)) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (server_hello->legacy_version != TLS_VSERVER_12) {
            return ALERT_ILLEGAL_PARAMETER;
        }
        if (server_hello->supported_version != TLS_VSERVER_13) {
            return ALERT_PROTOCOL_VERSION;
        }

        if (server_hello->is_support_ocsp_stapling || 
            server_hello->is_support_session_ticket || 
            server_hello->is_support_renegotiation_info || 
            server_hello->renegotiation_info.empty() == false|| 
            server_hello->alpn.empty() == false || 
            server_hello->scts.empty() == false) {
            return ALERT_UNSUPPORTED_EXTENSION;
        }

        if (server_hello->session_id != client_hello->session_id) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (server_hello->compression_method != TLS_COMPRESSION_METHOD_NONE) {
            return ALERT_ILLEGAL_PARAMETER; 
        }

        if (!is_contains(client_hello->cipher_suites, server_hello->cipher_suite)) {
            return ALERT_ILLEGAL_PARAMETER;
        }
        if (!load_tls13_cipher_suite_params(server_hello->cipher_suite, &session_.suite_param)) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (transcript_ == nullptr) {
            transcript_ = ssl::create_hash_context(session_.suite_param.algo);
            PUMP_ASSERT(transcript_);
        }

        const std::string &ch_buffer = pack_handshake_message(&client_hello_);
        PUMP_DEBUG_CHECK(ssl::update_hash(transcript_, (void_ptr)ch_buffer.data(), (int32_t)ch_buffer.size()));

        if (memcmp(server_hello->random, hello_retry_request_random, 32) == 0) {
            if (status_ == HANDSHAKER_RETRY_HELLO_SENT) {
                return ALERT_UNEXPECTED_MESSGAE;
            }
            return __send_hello_retry(msg);
        }

        const std::string &sh_buffer = pack_handshake_message(msg);
        PUMP_DEBUG_CHECK(ssl::update_hash(transcript_, (void_ptr)sh_buffer.data(), (int32_t)sh_buffer.size()));

        if (!server_hello->cookie.empty()) {
            return ALERT_UNSUPPORTED_EXTENSION;
        }

        if (server_hello->selected_group != TLS_CURVE_UNKNOWN) {
            return ALERT_DECODE_ERROR;
        }

        if (server_hello->selected_key_share.group == TLS_CURVE_UNKNOWN || 
            server_hello->selected_key_share.group != client_hello->key_shares[0].group) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (server_hello->has_selected_psk_identity) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        std::string shared_key = ssl::gen_ecdhe_shared_key(
                                    session_.ecdhe_param, 
                                    server_hello->selected_key_share.data);
        if (shared_key.empty()) {
            return ALERT_ILLEGAL_PARAMETER; 
        }

        std::string handshake_secret;
        {
            std::string secret = cipher_suite_device_secret(
                                    &session_.suite_param, 
                                    cipher_suite_extract(&session_.suite_param, "", ""), 
                                    "derived", 
                                    nullptr);
            handshake_secret = cipher_suite_extract(&session_.suite_param, secret, shared_key);
        }

        session_.client_secret = cipher_suite_device_secret(
                                    &session_.suite_param, 
                                    handshake_secret,
                                    CLIENT_HANDSHAKE_TRAFFIC_LABEL, 
                                    transcript_);

        session_.server_secret = cipher_suite_device_secret(
                                    &session_.suite_param, 
                                    handshake_secret,
                                    SERVER_HANDSHAKE_TRAFFIC_LABEL, 
                                    transcript_);

        {
            std::string secret = cipher_suite_device_secret(
                                    &session_.suite_param, 
                                    handshake_secret, 
                                    "derived", 
                                    nullptr);
            session_.master_secret = cipher_suite_extract(&session_.suite_param, secret, "");
        }
        
        status_ = HANDSHAKER_SERVER_HELLO_RECV;

        return true;
    }

    alert_code client_handshaker::__send_hello_retry(handshake_message *msg) {
        if (status_ != HANDSHAKER_CLIENT_HELLO_SENT) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        server_hello_message *server_hello = (server_hello_message*)msg->msg;
        PUMP_ASSERT(server_hello);

        client_hello_message *client_hello = (client_hello_message*)client_hello_.msg;
        PUMP_ASSERT(client_hello);

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
        PUMP_DEBUG_CHECK(ssl::update_hash(transcript_, hash_msg));

        const std::string& sh_buffer = pack_handshake_message(msg);
        ssl::update_hash(transcript_, (void_ptr)sh_buffer.data(), (int32_t)sh_buffer.size());

        // The only HelloRetryRequest extensions we support are key_share and
	    // cookie, and clients must abort the handshake if the HRR would not result
	    // in any change in the ClientHello.
        if (server_hello->selected_group == TLS_CURVE_UNKNOWN && server_hello->cookie.empty()) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (!server_hello->cookie.empty()) { 
            client_hello->cookie = server_hello->cookie;
        }

        if (server_hello->selected_key_share.group != TLS_CURVE_UNKNOWN) {
            return ALERT_DECODE_ERROR;
        }

        if (!is_contains(client_hello->supported_groups, server_hello->selected_group)) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (ssl::get_ecdhe_curve(session_.ecdhe_param) == server_hello->selected_group) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        ssl::free_ecdhe_parameter(session_.ecdhe_param);
        session_.ecdhe_param = ssl::create_ecdhe_parameter(server_hello->selected_group);
        if (session_.ecdhe_param == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }

        key_share ks;
        ks.group = server_hello->selected_group;
        ks.data = ssl::get_ecdhe_pubkey(session_.ecdhe_param);
        client_hello->key_shares[0] = std::move(ks);

        client_hello->is_support_early_data = false;

        // TODO: send client hello message.

        status_ = HANDSHAKER_RETRY_HELLO_SENT;

        return ALERT_NONE;
    }

    alert_code client_handshaker::__handle_encrypted_extensions(handshake_message *msg) {
        if (status_ != HANDSHAKER_SERVER_HELLO_RECV) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        encrypted_extensions_message *encrypted_extensions = (encrypted_extensions_message*)msg->msg;
        PUMP_ASSERT(encrypted_extensions);

        client_hello_message *client_hello = (client_hello_message*)client_hello_.msg;
        PUMP_ASSERT(client_hello);

        if (!is_contains(client_hello->alpns, encrypted_extensions->alpn)) {
            return ALERT_UNSUPPORTED_EXTENSION; 
        }
        session_.alpn = encrypted_extensions->alpn;

        if (client_hello->is_support_early_data && encrypted_extensions->is_support_early_data) {
            session_.enable_zero_rtt = true;
        }

        status_ = HANDSHAKER_ENCRYPTED_EXTENSIONS_RECV;

        return ALERT_NONE;
    }

    alert_code client_handshaker::__handle_certificate_request_tls13(handshake_message *msg) {
        if (status_ != HANDSHAKER_ENCRYPTED_EXTENSIONS_RECV) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        certificate_request_tls13_message *cert_request = (certificate_request_tls13_message*)msg->msg;
        PUMP_ASSERT(cert_request);

        cert_request_ = *cert_request;

        const std::string &buffer = pack_handshake_message(msg);
        ssl::update_hash(transcript_, (void_ptr)buffer.data(), (int32_t)buffer.size());

        status_ = HANDSHAKER_CARTIFICATE_REQUEST_RECV;

        return ALERT_NONE;
    }

    alert_code client_handshaker::__handle_certificate_tls13(handshake_message *msg) {
        if (status_ != HANDSHAKER_ENCRYPTED_EXTENSIONS_RECV &&
            status_ != HANDSHAKER_CARTIFICATE_REQUEST_RECV) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        certificate_tls13_message *cert = (certificate_tls13_message*)msg->msg;
        PUMP_ASSERT(cert);

        if (cert->certificates.empty()) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (!certificate_load(cert->certificates, session_.certs)) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (!ssl::verify_x509_certificates(session_.certs)) {
            return ALERT_BAD_CERTIFICATE;
        }

        session_.scts = cert->scts;
     
        session_.ocsp_staple = cert->ocsp_staple;

        status_ = HANDSHAKER_CARTIFICATE_RECV;

        return ALERT_NONE;
    }

    alert_code client_handshaker::__handle_certificate_verify(handshake_message *msg) {
        if (status_ != HANDSHAKER_CARTIFICATE_RECV) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        certificate_verify_message *cert_verify = (certificate_verify_message*)msg->msg;
        PUMP_ASSERT(cert_verify);

        client_hello_message *client_hello = (client_hello_message*)client_hello_.msg;
        PUMP_ASSERT(client_hello);

        if (!is_contains(client_hello->supported_signature_algorithms, cert_verify->signature_algorithm)) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        ssl::hash_algorithm sign_hash_algo = get_hash_algo_for_sign_algo(cert_verify->signature_algorithm);
        if (sign_hash_algo == ssl::HASH_UNKNOWN) {
            return ALERT_ILLEGAL_PARAMETER; 
        }

        ssl::signature_algorithm sign_algo = transfor_sign_algo(cert_verify->signature_algorithm);
        if (sign_algo == ssl::TLS_SIGNATURE_UNKNOWN) {
            return ALERT_ILLEGAL_PARAMETER; 
        }

        std::string sign_hash;
        PUMP_DEBUG_CHECK(ssl::sum_hash(transcript_, sign_hash));
        ssl::hash_context_ptr sign_hash_ctx = ssl::create_hash_context(sign_hash_algo);
        ssl::update_hash(sign_hash_ctx, signature_padding, (int32_t)sizeof(signature_padding));
        ssl::update_hash(sign_hash_ctx, SERVER_SIGNATURE_CONTEXT, (int32_t)strlen(SERVER_SIGNATURE_CONTEXT));
        PUMP_DEBUG_CHECK(ssl::update_hash(sign_hash_ctx, sign_hash));
        ssl::free_hash_context(sign_hash_ctx);

        if (!ssl::verify_signature(sign_algo, sign_hash_algo, session_.certs[0], sign_hash, cert_verify->signature)) {
            return ALERT_DECRYPT_ERROR;
        }

        const std::string &buffer = pack_handshake_message(msg);
        ssl::update_hash(transcript_, (void_ptr)buffer.data(), (int32_t)buffer.size());

        status_ = HANDSHAKER_CARTIFICATE_VERIFY_RECV;

        return ALERT_NONE;
    }

}
}
}
}