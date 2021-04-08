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
#include "pump/codec/base64.h"
#include "pump/toolkit/features.h"
#include "pump/protocol/quic/tls/utils.h"
#include "pump/protocol/quic/tls/client.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    client_handshaker::client_handshaker()
      : status_(HANDSHAKE_INIT), 
        hello_(nullptr), 
        transcript_(nullptr) {
    }

    client_handshaker::~client_handshaker() {
    }

    bool client_handshaker::handshake(const config &cfg) {
        if (status_ != HANDSHAKE_INIT) {
            return false;
        }

        session_.alpn = cfg.alpn;
        session_.server_name = cfg.server_name;

        if (!cfg.cert_pem.empty()) {
            auto cert = ssl::load_x509_certificate_pem(cfg.cert_pem);
            if (cert == nullptr) {
                return false;
            }
            session_.certs.push_back(cert);
        }

        if (!__send_client_hello()) {
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
        case TLS_MSG_ENCRYPTED_EXTENSIONS:
            code = __handle_encrypted_extensions(msg);
            break;
        case TLS_MSG_CERTIFICATE_REQUEST:
            code = __handle_certificate_request_tls13(msg);
            break;
        case TLS_MSG_CERTIFICATE:
            code = __handle_certificate_tls13(msg);
            break;
        case TLS_MSG_CERTIFICATE_VERIFY:
            code = __handle_certificate_verify(msg);
            break;
        case TLS_MSG_FINISHED:
            code = __handle_finished(msg);
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

    bool client_handshaker::__send_client_hello() {
        if (session_.server_name.empty()) {
            return false;
        }

        if (session_.alpn.empty() || session_.alpn.size() > 255) {
            return false;
        }

        if ((hello_ = new_handshake_message(TLS_MSG_CLIENT_HELLO)) == nullptr) {
            return false;
        }
        auto hello = (client_hello_message*)hello_->raw_msg;

        hello->legacy_version = TLS_VSERVER_12;

        std::default_random_engine random;
        for (int32_t i = 0; i < (int32_t)sizeof(hello->random); i++) {
            hello->random[i]= random();
        }

        // Just include tls 1.3 cipher suites.
        hello->cipher_suites.push_back(TLS_AES_128_GCM_SHA256);
        hello->cipher_suites.push_back(TLS_CHACHA20_POLY1305_SHA256);
        hello->cipher_suites.push_back(TLS_AES_256_GCM_SHA384);

        hello->compression_methods.push_back(TLS_COMPRESSION_METHOD_NONE);

        hello->server_name = session_.server_name;

        // TODO: not support ocsp staple ?
        hello->is_support_ocsp_stapling = false;

        // TODO: not support scts ?
        hello->is_support_scts = false;

        hello->supported_groups.push_back(ssl::TLS_CURVE_X25519);
        hello->supported_groups.push_back(ssl::TLS_CURVE_P256);
        hello->supported_groups.push_back(ssl::TLS_CURVE_P384);
        hello->supported_groups.push_back(ssl::TLS_CURVE_P521);

        hello->supported_points.push_back(TLS_POINT_FORMAT_UNCOMPRESSED);

        // Not support session ticket.
        hello->is_support_session_ticket = false;

        // Just support tls 1.3 signature algorithms.
        hello->supported_signature_schemes.push_back(ssl::TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256);
        hello->supported_signature_schemes.push_back(ssl::TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384);
        hello->supported_signature_schemes.push_back(ssl::TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512);

        hello->is_support_renegotiation_info = false;

        hello->alpns.push_back(session_.alpn);

        // Just support tls 1.3 version.
        hello->supported_versions.push_back(TLS_VSERVER_13);

        if (hello->supported_versions[0] == TLS_VSERVER_13) {
            session_.ecdhe_param = ssl::create_ecdhe_parameter(ssl::TLS_CURVE_X25519);
            if (session_.ecdhe_param == nullptr) {
                return false;
            }
            key_share ks;
            ks.group = ssl::TLS_CURVE_X25519;
            ks.data = ssl::get_ecdhe_pubkey(session_.ecdhe_param);
            hello->key_shares.push_back(std::move(ks));
        }

        // Not support eraly data.
        hello->is_support_early_data = false;

        status_ = HANDSHAKE_CLIENT_HELLO_SENT;

        __send_handshake_message(hello_, false);

        return true;
    }

    alert_code client_handshaker::__handle_server_hello(handshake_message *msg) {
        if (status_ != HANDSHAKE_CLIENT_HELLO_SENT &&
            status_ != HANDSHAKE_RETRY_HELLO_SENT) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        auto server_hello = (server_hello_message*)msg->raw_msg;
        PUMP_ASSERT(server_hello);

        auto client_hello = (client_hello_message*)hello_->raw_msg;
        PUMP_ASSERT(client_hello);

        if (memcmp(server_hello->random + 24, DOWNGRRADE_CANARY_TLS11, 8) == 0 || 
            memcmp(server_hello->random + 24, DOWNGRRADE_CANARY_TLS12, 8) == 0) {
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

        __write_transcript(pack_handshake_message(hello_));

        if (memcmp(server_hello->random, hello_retry_request_random, 32) == 0) {
            return __send_hello_retry(msg);
        }

        if (!server_hello->cookie.empty()) {
            return ALERT_UNSUPPORTED_EXTENSION;
        }

        if (server_hello->selected_group != ssl::TLS_CURVE_UNKNOWN) {
            return ALERT_DECODE_ERROR;
        }

        if (server_hello->selected_key_share.group == ssl::TLS_CURVE_UNKNOWN || 
            server_hello->selected_key_share.group != client_hello->key_shares[0].group) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (server_hello->has_selected_psk_identity) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        __write_transcript(pack_handshake_message(msg));

        {
            auto shared_key = ssl::gen_ecdhe_shared_key(
                                session_.ecdhe_param,
                                server_hello->selected_key_share.data);
            auto secret = cipher_suite_device_secret(
                            &session_.suite_param, 
                            cipher_suite_extract(&session_.suite_param, "", ""), 
                            "derived", 
                            nullptr);
            session_.handshake_secret = cipher_suite_extract(&session_.suite_param, secret, shared_key);
            auto handshake_secret_base64 = codec::base64_encode(session_.handshake_secret);
            PUMP_DEBUG_LOG("client handshaker handshake_secret_base64: %s", handshake_secret_base64.c_str());
        }

        session_.client_secret = cipher_suite_device_secret(
                                    &session_.suite_param, 
                                    session_.handshake_secret,
                                    CLIENT_HANDSHAKE_TRAFFIC_LABEL, 
                                    transcript_);
        auto client_secret_base64 = codec::base64_encode(session_.client_secret);
        PUMP_DEBUG_LOG("client handshaker client_secret_base64: %s", client_secret_base64.c_str());

        session_.server_secret = cipher_suite_device_secret(
                                    &session_.suite_param, 
                                    session_.handshake_secret,
                                    SERVER_HANDSHAKE_TRAFFIC_LABEL, 
                                    transcript_);
        auto server_secret_base64 = codec::base64_encode(session_.server_secret);
        PUMP_DEBUG_LOG("client handshaker server_secret_base64: %s", server_secret_base64.c_str());

        {
            auto secret = cipher_suite_device_secret(
                            &session_.suite_param, 
                            session_.handshake_secret, 
                            "derived", 
                            nullptr);
            session_.master_secret = cipher_suite_extract(&session_.suite_param, secret, "");
            auto master_secret_base64 = codec::base64_encode(session_.master_secret);
            PUMP_DEBUG_LOG("client handshaker master_secret_base64: %s", master_secret_base64.c_str());
        }
        
        status_ = HANDSHAKE_SERVER_HELLO_RECV;

        return ALERT_NONE;
    }

    alert_code client_handshaker::__send_hello_retry(handshake_message *msg) {
        if (status_ == HANDSHAKE_RETRY_HELLO_SENT) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        auto server_hello = (server_hello_message*)msg->raw_msg;
        PUMP_ASSERT(server_hello);

        auto client_hello = (client_hello_message*)hello_->raw_msg;
        PUMP_ASSERT(client_hello);

        // The only HelloRetryRequest extensions we support are key_share and
	    // cookie, and clients must abort the handshake if the HRR would not result
	    // in any change in the ClientHello.
        if (server_hello->selected_group == ssl::TLS_CURVE_UNKNOWN && 
            server_hello->cookie.empty()) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (!server_hello->cookie.empty()) { 
            client_hello->cookie = server_hello->cookie;
        }

        if (server_hello->selected_key_share.group != ssl::TLS_CURVE_UNKNOWN) {
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

        status_ = HANDSHAKE_RETRY_HELLO_SENT;

        __write_transcript(pack_message_hash(__reset_transcript()));
        __write_transcript(pack_handshake_message(msg));

        __send_handshake_message(hello_, false);

        return ALERT_NONE;
    }

    alert_code client_handshaker::__handle_encrypted_extensions(handshake_message *msg) {
        if (status_ != HANDSHAKE_SERVER_HELLO_RECV) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        auto encrypted_extensions = (encrypted_extensions_message*)msg->raw_msg;
        PUMP_ASSERT(encrypted_extensions);

        auto client_hello = (client_hello_message*)hello_->raw_msg;
        PUMP_ASSERT(client_hello);

        if (!is_contains(client_hello->alpns, encrypted_extensions->alpn)) {
            return ALERT_UNSUPPORTED_EXTENSION; 
        }

        if (client_hello->is_support_early_data && encrypted_extensions->is_support_early_data) {
            session_.enable_zero_rtt = true;
        }

        status_ = HANDSHAKE_ENCRYPTED_EXTENSIONS_RECV;

        __write_transcript(pack_handshake_message(msg));

        return ALERT_NONE;
    }

    alert_code client_handshaker::__handle_certificate_request_tls13(handshake_message *msg) {
        if (status_ != HANDSHAKE_ENCRYPTED_EXTENSIONS_RECV) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        auto cert_request = (certificate_request_tls13_message*)msg->raw_msg;
        PUMP_ASSERT(cert_request);

        cert_request_ = *cert_request;

        status_ = HANDSHAKE_CARTIFICATE_REQUEST_RECV;

        __write_transcript(pack_handshake_message(msg));

        return ALERT_NONE;
    }

    alert_code client_handshaker::__handle_certificate_tls13(handshake_message *msg) {
        if (status_ != HANDSHAKE_ENCRYPTED_EXTENSIONS_RECV &&
            status_ != HANDSHAKE_CARTIFICATE_REQUEST_RECV) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        auto cert_tls13 = (certificate_tls13_message*)msg->raw_msg;
        PUMP_ASSERT(cert_tls13);

        if (cert_tls13->certificates.empty()) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (!certificate_load(cert_tls13->certificates, session_.peer_certs)) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (!ssl::verify_x509_certificates(session_.peer_certs)) {
            return ALERT_BAD_CERTIFICATE;
        }

        if (cert_tls13->is_support_scts && !cert_tls13->scts.empty()) {
            session_.scts = cert_tls13->scts;
        }
        
        if (cert_tls13->is_support_ocsp_stapling) {
            session_.ocsp_staple = cert_tls13->ocsp_staple;
        }

        status_ = HANDSHAKE_CARTIFICATE_RECV;

        __write_transcript(pack_handshake_message(msg));

        return ALERT_NONE;
    }

    alert_code client_handshaker::__handle_certificate_verify(handshake_message *msg) {
        if (status_ != HANDSHAKE_CARTIFICATE_RECV) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        auto cert_verify = (certificate_verify_message*)msg->raw_msg;
        PUMP_ASSERT(cert_verify);

        auto client_hello = (client_hello_message*)hello_->raw_msg;
        PUMP_ASSERT(client_hello);

        if (!is_contains(client_hello->supported_signature_schemes, cert_verify->signature_scheme)) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        auto hash_algo = transform_to_hash_algo(cert_verify->signature_scheme);
        if (hash_algo == ssl::HASH_UNKNOWN) {
            return ALERT_ILLEGAL_PARAMETER; 
        }

        auto sign_algo = transform_to_sign_algo(cert_verify->signature_scheme);
        if (sign_algo == ssl::TLS_SIGN_ALGO_UNKNOWN) {
            return ALERT_ILLEGAL_PARAMETER; 
        }

        auto sign = sign_message(hash_algo, SERVER_SIGNATURE_CONTEXT, ssl::sum_hash(transcript_));
        if (!ssl::verify_signature(session_.certs[0], sign_algo, hash_algo, sign, cert_verify->signature)) {
            return ALERT_DECRYPT_ERROR;
        }

        status_ = HANDSHAKE_CARTIFICATE_VERIFY_RECV;

        __write_transcript(pack_handshake_message(msg));

        return ALERT_NONE;
    }

    alert_code client_handshaker::__handle_finished(handshake_message *msg) {
        if (status_ != HANDSHAKE_CARTIFICATE_RECV &&
            status_ != HANDSHAKE_CARTIFICATE_VERIFY_RECV) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        auto finished = (finished_message*)msg->raw_msg;
        PUMP_ASSERT(finished);

        // https://tools.ietf.org/html/rfc8446#section-4.4.4
        // https://tools.ietf.org/html/rfc8446#section-4.2.11.2
        auto finished_key = hkdf_expand_label(
                                session_.suite_param.algo, 
                                session_.server_secret, 
                                "", 
                                "finished", 
                                ssl::hash_digest_length(session_.suite_param.algo));
        auto verify_data = ssl::sum_hmac(
                            session_.suite_param.algo, 
                            finished_key, 
                            ssl::sum_hash(transcript_));
        auto verify_data_base64 = codec::base64_encode(verify_data);
        PUMP_DEBUG_LOG("client handshaker server verify_data_base64: %s", verify_data_base64.c_str());
        if (verify_data != finished->verify_data) {
            return ALERT_DECRYPT_ERROR;
        }

        __write_transcript(pack_handshake_message(msg));

        session_.traffic_secret = cipher_suite_device_secret(
                                    &session_.suite_param, 
                                    session_.master_secret, 
                                    CLIENT_APPLICATION_TRAFFIC_LABEL, 
                                    transcript_);
        auto traffic_secret_base64 = codec::base64_encode(session_.traffic_secret);
        PUMP_DEBUG_LOG("client handshaker traffic_secret_base64: %s", traffic_secret_base64.c_str());

        session_.server_secret = cipher_suite_device_secret(
                                    &session_.suite_param, 
                                    session_.master_secret, 
                                    SERVER_APPLICATION_TRAFFIC_LABEL, 
                                    transcript_);
        auto server_secret_base64 = codec::base64_encode(session_.server_secret);
        PUMP_DEBUG_LOG("client handshaker server_secret_base64: %s", server_secret_base64.c_str());

        // https://tools.ietf.org/html/rfc8446#section-7.5
        session_.export_master_secret = cipher_suite_device_secret(
                                            &session_.suite_param, 
                                            session_.master_secret, 
                                            EXPORTER_LABEL, 
                                            transcript_);
        auto export_master_secret_base64 = codec::base64_encode(session_.export_master_secret);
        PUMP_DEBUG_LOG("client handshaker export_master_secret_base64: %s", export_master_secret_base64.c_str());

        status_ = HANDSHAKE_FINISHED_RECV;

        alert_code code = ALERT_NONE;
        if ((code = __send_certificate_tls13()) != ALERT_NONE ||
            (code = __send_finished()) != ALERT_NONE) {
            return code;
        }

        return ALERT_NONE;
    }

    alert_code client_handshaker::__send_certificate_tls13() {
        if (status_ != HANDSHAKE_FINISHED_RECV) {
            return ALERT_INTERNAL_ERROR;
        }

        auto msg = new_handshake_message(TLS_MSG_CERTIFICATE);
        if (msg == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }
        toolkit::defer cleanup([&](){
            delete_handshake_message(msg);
        });
        auto cert_tls13 = (certificate_tls13_message*)msg->raw_msg;

        if (session_.certs.empty()) {
            cert_tls13->is_support_scts = false;
            cert_tls13->is_support_ocsp_stapling = false;
        } else {
            // TODO: not support ocsp staple ?
            cert_tls13->is_support_ocsp_stapling = false;
            cert_tls13->is_support_scts = cert_request_.is_support_scts && ssl::has_x509_scts(session_.certs[0]);
            cert_tls13->certificates.push_back(ssl::read_x509_certificate_raw(session_.certs[0]));
        }

        status_ = HANDSHAKE_CARTIFICATE_SENT;

        __send_handshake_message(msg);

        return ALERT_NONE;
    }

    alert_code client_handshaker::__send_certificate_verify() {
        if (status_ != HANDSHAKE_CARTIFICATE_SENT) {
            return ALERT_INTERNAL_ERROR;
        }

        if (!session_.certs.empty()) {
            auto msg = new_handshake_message(TLS_MSG_CERTIFICATE_VERIFY);
            if (msg == nullptr) {
                return ALERT_INTERNAL_ERROR;
            }
            toolkit::defer cleanup([&](){
                delete_handshake_message(msg);
            });
            auto cert_verify = (certificate_verify_message*)msg->raw_msg;

            cert_verify->has_signature_scheme = true;
            cert_verify->signature_scheme = ssl::get_x509_signature_scheme(session_.certs[0]);

            auto hash_algo = transform_to_hash_algo(cert_verify->signature_scheme);
            if (hash_algo == ssl::HASH_UNKNOWN) {
                return ALERT_INTERNAL_ERROR;
            }

            auto sign_algo = transform_to_sign_algo(cert_verify->signature_scheme);
            if (sign_algo == ssl::TLS_SIGN_ALGO_UNKNOWN) {
                return ALERT_INTERNAL_ERROR;
            }

            auto sign = sign_message(hash_algo, SERVER_SIGNATURE_CONTEXT, ssl::sum_hash(transcript_));
            if (!ssl::do_signature(session_.certs[0], sign_algo, sign_algo, sign, cert_verify->signature)) {
                return ALERT_INTERNAL_ERROR;
            }

            status_ = HANDSHAKE_CARTIFICATE_VERIFY_SENT;

            __send_handshake_message(msg);
        }

        return ALERT_NONE;
    }

    alert_code client_handshaker::__send_finished() {
        if (status_ != HANDSHAKE_CARTIFICATE_SENT &&
            status_ != HANDSHAKE_CARTIFICATE_VERIFY_SENT) {
            return ALERT_INTERNAL_ERROR;
        }

        auto msg = new_handshake_message(TLS_MSG_FINISHED);
        if (msg == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }
        toolkit::defer cleanup([&](){
            delete_handshake_message(msg);
        });
        auto finished = (finished_message*)msg->raw_msg;

        // https://tools.ietf.org/html/rfc8446#section-4.4.4
        // https://tools.ietf.org/html/rfc8446#section-4.2.11.2
        auto finished_key = hkdf_expand_label(
                                session_.suite_param.algo, 
                                session_.client_secret, 
                                "", 
                                "finished", 
                                ssl::hash_digest_length(session_.suite_param.algo));
        finished->verify_data = ssl::sum_hmac(
                                    session_.suite_param.algo, 
                                    finished_key, 
                                    ssl::sum_hash(transcript_));
        auto verify_data_base64 = codec::base64_encode(finished->verify_data);
        PUMP_DEBUG_LOG("client handshaker client verify_data_base64: %s", verify_data_base64.c_str());

        status_ = HANDSHAKE_SUCCESS;

        __send_handshake_message(msg);

        if (finished_callback_) {
            finished_callback_(session_);
        }

        return ALERT_NONE;
    }

    std::string client_handshaker::__reset_transcript() {
        PUMP_ASSERT(transcript_);
        std::string hash = ssl::sum_hash(transcript_);
        ssl::free_hash_context(transcript_);
        transcript_ = ssl::create_hash_context(session_.suite_param.algo);
        PUMP_ASSERT(transcript_);
        return std::forward<std::string>(hash);
    }

    void client_handshaker::__write_transcript(const std::string &data) {
        if (transcript_ == nullptr) {
            transcript_ = ssl::create_hash_context(session_.suite_param.algo);
            PUMP_ASSERT(transcript_);
        }
        PUMP_DEBUG_CHECK(ssl::update_hash(transcript_, data));
    }

}
}
}
}