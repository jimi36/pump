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
#include "pump/protocol/quic/tls/utils.h"
#include "pump/protocol/quic/tls/server.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    server_handshaker::server_handshaker()
      : status_(HANDSHAKE_INIT),
        hello_(nullptr),
        transcript_(nullptr) {
    }

    server_handshaker::~server_handshaker() {
    }

    bool server_handshaker::handshake(const config &cfg) {
        if (status_ != HANDSHAKE_INIT) {
            return false;
        }

        cfg_ = cfg;

        return true;
    }

    bool server_handshaker::handshake(handshake_message *msg) {
        alert_code code = ALERT_NONE;
        switch (msg->type)
        {
        case TLS_MSG_CLIENT_HELLO:
            code = __handle_client_hello(msg);
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

    alert_code server_handshaker::__handle_client_hello(handshake_message *msg) {
        if (status_ != HANDSHAKE_INIT && 
            status_ != HANDSHAKE_HELLO_REQUEST_SEND) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        client_hello_message *client_hello = (client_hello_message*)msg->msg;
        PUMP_ASSERT(client_hello);

        if (client_hello->legacy_version != TLS_VSERVER_12) {
            return ALERT_ILLEGAL_PARAMETER;
        }
        
        version_type version13 = TLS_VSERVER_13;
        if (client_hello->supported_versions.empty() || 
            !is_contains(client_hello->supported_versions, version13)) {
            return ALERT_PROTOCOL_VERSION;
        }

        if (client_hello->compression_methods.empty() ||
            client_hello->compression_methods.size() != 1 || 
            client_hello->compression_methods[0] != TLS_COMPRESSION_METHOD_NONE) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (!client_hello->renegotiation_info.empty()) {
            return ALERT_HANDSHAKE_FAILURE;
        }

        if (client_hello->supported_signature_schemes.empty()) {
            return ALERT_MISSING_EXTENSION;
        }

        if (!is_contains(client_hello->alpns, cfg_.alpn)) {
            return ALERT_ILLEGAL_PARAMETER;
        }
        session_.alpn = cfg_.alpn;

        // Check cipher suite.
        cipher_suite_type selected_cipher_suite = TLS_CIPHER_SUITE_UNKNOWN;
        for (int32_t i = 0; i < supported_cipher_suites_count; i++) {
            cipher_suite_type cs =  supported_cipher_suites[i];
            if (is_contains(client_hello->cipher_suites, cs)) {
                if (!load_tls13_cipher_suite_params(cs, &session_.suite_param)) {
                    return ALERT_ILLEGAL_PARAMETER;
                }
                selected_cipher_suite = cs;
                break;
            }
        }
        if (selected_cipher_suite == TLS_CIPHER_SUITE_UNKNOWN) {
            return ALERT_HANDSHAKE_FAILURE;
        }

        // Check curve group.
        key_share *client_ks = nullptr;
        ssl::curve_type selected_curve = ssl::TLS_CURVE_UNKNOWN;
        for (int32_t i = 0; i < supported_curve_groups_count; i++) {
            for (int32_t j1 = 0; j1 < (int32_t)client_hello->key_shares.size(); j1++) {
                if (client_hello->key_shares[j1].group == supported_curve_groups[i]) {
                    client_ks = &client_hello->key_shares[j1];
                    selected_curve = client_ks->group;
                    break;
                }
            }
            if (client_ks != nullptr) {
                break;
            }
            if (selected_curve == ssl::TLS_CURVE_UNKNOWN) {
                for (int32_t j2 = 0; j2 < (int32_t)client_hello->supported_groups.size(); j2++) {
                    if (client_hello->supported_groups[j2] == supported_curve_groups[i]) {
                        selected_curve = client_hello->supported_groups[j2];
                        break;
                    }
                }
            }
        }
        if (selected_curve == ssl::TLS_CURVE_UNKNOWN) {
            return ALERT_HANDSHAKE_FAILURE;
        }

        client_hello_ = *client_hello;

        __write_transcript(pack_handshake_message(msg));

        if (client_ks == nullptr) {
            return __send_hello_retry_request(selected_cipher_suite, selected_curve);
        }

        // Load certificate and certificate signature scheme.
        ssl::x509_certificate_ptr cert = nullptr;
        if (cfg_.cert_pem.empty()) {
            cert = ssl::generate_x509_certificate(client_hello->supported_signature_schemes[0]);
        } else {
            cert = ssl::load_x509_certificate_pem(cfg_.cert_pem);
        }
        if (cert == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }
        ssl::signature_scheme scheme = ssl::get_x509_signature_scheme(cert);
        if (scheme == ssl::TLS_SIGN_SCHE_UNKNOWN) {
            return ALERT_INTERNAL_ERROR;
        }
        if (!is_contains(client_hello->supported_signature_schemes, scheme)) {
            return ALERT_HANDSHAKE_FAILURE;
        }
        session_.certs.push_back(cert);

        session_.ecdhe_param = ssl::create_ecdhe_parameter(selected_curve);
        if (session_.ecdhe_param == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }

        if (!client_hello->server_name.empty()) {
            session_.server_name = client_hello->server_name;
        }

        status_ = HANDSHAKE_CLIENT_HELLO_RECV;

        alert_code code = ALERT_NONE;
        if ((code = __send_server_hello(selected_cipher_suite, selected_curve, scheme)) != ALERT_NONE || 
            (code = __send_encrypted_extensions()) != ALERT_NONE ||
            (code = __send_certificate()) != ALERT_NONE ||
            (code = __send_finished()) != ALERT_NONE) {
            return code;
        }

        {
            std::string secret = cipher_suite_device_secret(
                                    &session_.suite_param, 
                                    session_.handshake_secret, 
                                    "derived", 
                                    nullptr);
            session_.master_secret = cipher_suite_extract(&session_.suite_param, secret, "");
            std::string master_secret_base64 = codec::base64_encode(session_.master_secret);
            PUMP_DEBUG_LOG("server handshaker master_secret_base64: %s", master_secret_base64.c_str());
        }

        session_.traffic_secret = cipher_suite_device_secret(
                                    &session_.suite_param, 
                                    session_.master_secret,
                                    CLIENT_APPLICATION_TRAFFIC_LABEL, 
                                    transcript_);
        std::string traffic_secret_base64 = codec::base64_encode(session_.traffic_secret);
        PUMP_DEBUG_LOG("server handshaker traffic_secret_base64: %s", traffic_secret_base64.c_str());

        session_.server_secret = cipher_suite_device_secret(
                                    &session_.suite_param, 
                                    session_.master_secret,
                                    SERVER_APPLICATION_TRAFFIC_LABEL, 
                                    transcript_);
        std::string server_secret_base64 = codec::base64_encode(session_.server_secret);
        PUMP_DEBUG_LOG("server handshaker server_secret_base64: %s", server_secret_base64.c_str());

        // https://tools.ietf.org/html/rfc8446#section-7.5
        session_.export_master_secret = cipher_suite_device_secret(
                                            &session_.suite_param, 
                                            session_.master_secret, 
                                            EXPORTER_LABEL, 
                                            transcript_);
        std::string export_master_secret_base64 = codec::base64_encode(session_.export_master_secret);
        PUMP_DEBUG_LOG("server handshaker export_master_secret_base64: %s", export_master_secret_base64.c_str());

        return ALERT_NONE;
    }

    alert_code server_handshaker::__send_hello_retry_request(
        cipher_suite_type selected_cipher_suite,
        ssl::curve_type selected_curve) {
        if (status_ != HANDSHAKE_INIT) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        handshake_message *msg = new_handshake_message(TLS_MSG_SERVER_HELLO);
        if (msg == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }
        server_hello_message *server_hello = (server_hello_message*)msg->msg;
        PUMP_ASSERT(server_hello);

        server_hello->legacy_version = TLS_VSERVER_12;

        server_hello->supported_version = TLS_VSERVER_13;

        server_hello->session_id = client_hello_.session_id;

        server_hello->compression_method = TLS_COMPRESSION_METHOD_NONE;

        server_hello->selected_group = selected_curve;

        server_hello->cipher_suite = selected_cipher_suite;

        memcpy(server_hello->random, hello_retry_request_random, 32);

        status_ = HANDSHAKE_HELLO_REQUEST_SEND;
  
        __write_transcript(pack_message_hash(__reset_transcript()));

        __send_handshake_message(msg);
        
        delete_handshake_message(msg);

        return ALERT_NONE;
    }

    alert_code server_handshaker::__send_server_hello(
        cipher_suite_type selected_cipher_suite,
        ssl::curve_type selected_curve, 
        ssl::signature_scheme selected_scheme) {
        if (status_ != HANDSHAKE_CLIENT_HELLO_RECV) {
            return ALERT_INTERNAL_ERROR;
        }

        hello_ = new_handshake_message(TLS_MSG_SERVER_HELLO);
        if (hello_ == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }
        server_hello_message *server_hello = (server_hello_message*)hello_->msg;
        PUMP_ASSERT(server_hello);

        server_hello->legacy_version = TLS_VSERVER_12;

        server_hello->supported_version = TLS_VSERVER_13;

        server_hello->compression_method = TLS_COMPRESSION_METHOD_NONE;

        server_hello->cipher_suite = selected_cipher_suite;

        server_hello->session_id = client_hello_.session_id;

        server_hello->has_selected_key_share = true;
        server_hello->selected_key_share.group = selected_curve;
        server_hello->selected_key_share.data = ssl::get_ecdhe_pubkey(session_.ecdhe_param);

        memcpy(server_hello->random, client_hello_.random, 32);

        status_ = HANDSHAKE_SERVER_HELLO_SENT;
   
        __send_handshake_message(hello_);

        return ALERT_NONE;
    }

    alert_code server_handshaker::__send_encrypted_extensions() {
        if (status_ != HANDSHAKE_SERVER_HELLO_SENT) {
            return ALERT_INTERNAL_ERROR;
        }

        handshake_message *msg = new_handshake_message(TLS_MSG_ENCRYPTED_EXTENSIONS);
        if (msg == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }
        encrypted_extensions_message *encrypted_extensions = (encrypted_extensions_message*)msg->msg;
        PUMP_ASSERT(encrypted_extensions);

        encrypted_extensions->is_support_early_data = false;

        encrypted_extensions->alpn = session_.alpn;

        {
            std::string secret = cipher_suite_device_secret(
                                    &session_.suite_param, 
                                    cipher_suite_extract(&session_.suite_param, "", ""), 
                                    "derived", 
                                    nullptr);
            std::string shared_key = ssl::gen_ecdhe_shared_key(
                                        session_.ecdhe_param, 
                                        client_hello_.key_shares[0].data);
            session_.handshake_secret = cipher_suite_extract(&session_.suite_param, secret, shared_key);
            std::string handshake_secret_base64 = codec::base64_encode(session_.handshake_secret);
            PUMP_DEBUG_LOG("server handshaker handshake_secret_base64: %s", handshake_secret_base64.c_str());
        }

        session_.client_secret = cipher_suite_device_secret(
                                    &session_.suite_param, 
                                    session_.handshake_secret,
                                    CLIENT_HANDSHAKE_TRAFFIC_LABEL, 
                                    transcript_);
        std::string client_secret_base64 = codec::base64_encode(session_.client_secret);
        PUMP_DEBUG_LOG("server handshaker client_secret_base64: %s", client_secret_base64.c_str());

        session_.server_secret = cipher_suite_device_secret(
                                    &session_.suite_param, 
                                    session_.handshake_secret,
                                    SERVER_HANDSHAKE_TRAFFIC_LABEL, 
                                    transcript_);
        std::string server_secret_base64 = codec::base64_encode(session_.server_secret);
        PUMP_DEBUG_LOG("server handshaker server_secret_base64: %s", server_secret_base64.c_str());

        status_ = HANDSHAKE_ENCRYPTED_EXTENSIONS_SENT;

        __send_handshake_message(msg);

        delete_handshake_message(msg);

        return ALERT_NONE;
    }

    alert_code server_handshaker::__send_certificate_request() {
        if (status_ != HANDSHAKE_ENCRYPTED_EXTENSIONS_SENT) {
            return ALERT_INTERNAL_ERROR;
        }

        handshake_message *msg = new_handshake_message(TLS_MSG_CERTIFICATE_REQUEST);
        if (msg == nullptr) {
            return false;
        }
        certificate_request_tls13_message *certificate_request = (certificate_request_tls13_message*)msg->msg;
        PUMP_ASSERT(certificate_request);

        certificate_request->is_support_scts = true;

        certificate_request->is_support_ocsp_stapling = true;

        certificate_request->supported_signature_schemes.assign(
            supported_signature_schemes, 
            supported_signature_schemes + supported_signature_schemes_count);

        status_ = HANDSHAKE_CARTIFICATE_REQUEST_SENT;

        __send_handshake_message(msg);

        delete_handshake_message(msg);

        return ALERT_NONE;
    }

    alert_code server_handshaker::__send_certificate() {
        if (status_ != HANDSHAKE_CARTIFICATE_REQUEST_SENT) {
            return ALERT_INTERNAL_ERROR;
        }

        handshake_message *msg = new_handshake_message(TLS_MSG_CERTIFICATE);
        if (msg == nullptr) {
            return false;
        }
        certificate_tls13_message *cert_tls13 = (certificate_tls13_message*)msg->msg;
        PUMP_ASSERT(cert_tls13);

        cert_tls13->certificates.push_back(cfg_.cert_pem);

        cert_tls13->is_support_scts = client_hello_.is_support_scts;

        cert_tls13->is_support_ocsp_stapling = client_hello_.is_support_ocsp_stapling;

        status_ = HANDSHAKE_CARTIFICATE_SENT;

        __send_handshake_message(msg);

        delete_handshake_message(msg);

        return ALERT_NONE;
    }

    alert_code server_handshaker::__send_certificate_verify() {
        if (status_ != HANDSHAKE_CARTIFICATE_SENT) {
            return ALERT_INTERNAL_ERROR;
        }

        handshake_message *msg = new_handshake_message(TLS_MSG_CERTIFICATE_VERIFY);
        if (msg == nullptr) {
            return false;
        }
        certificate_verify_message *cert_verify = (certificate_verify_message*)msg->msg;
        PUMP_ASSERT(cert_verify);

        cert_verify->has_signature_scheme = true;

        cert_verify->signature_scheme = ssl::get_x509_signature_scheme(session_.certs[0]);

        ssl::hash_algorithm hash_algo = transform_to_hash_algo(cert_verify->signature_scheme);
        if (hash_algo == ssl::HASH_UNKNOWN) {
            return ALERT_INTERNAL_ERROR;
        }

        ssl::signature_algorithm sign_algo = transform_to_sign_algo(cert_verify->signature_scheme);
        if (sign_algo == ssl::TLS_SIGN_ALGO_UNKNOWN) {
            return ALERT_INTERNAL_ERROR;
        }

        std::string sign = sign_message(hash_algo, SERVER_SIGNATURE_CONTEXT, ssl::sum_hash(transcript_));
        if (!ssl::do_signature(session_.certs[0], sign_algo, sign_algo, sign, cert_verify->signature)) {
            return ALERT_INTERNAL_ERROR;
        }

        status_ = HANDSHAKE_CARTIFICATE_VERIFY_SENT;

        __send_handshake_message(msg);

        delete_handshake_message(msg);

        return ALERT_NONE;
    }

    alert_code server_handshaker::__send_finished() {
        if (status_ != HANDSHAKE_CARTIFICATE_SENT && 
            status_ != HANDSHAKE_CARTIFICATE_VERIFY_SENT) {
            return ALERT_INTERNAL_ERROR;
        }

        handshake_message *msg = new_handshake_message(TLS_MSG_FINISHED);
        if (msg == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }
        finished_message *finished = (finished_message*)msg->msg;
        PUMP_ASSERT(finished);

        std::string finished_key = hkdf_expand_label(
                                    session_.suite_param.algo, 
                                    session_.server_secret, 
                                    "", 
                                    "finished", 
                                    ssl::hash_digest_length(session_.suite_param.algo));
        std::string finished_key_base64 = codec::base64_encode(finished_key);
        PUMP_DEBUG_LOG("server handshaker finished_key_base64: %s", finished_key_base64.c_str());

        finished->verify_data = ssl::sum_hmac(
                                    session_.suite_param.algo, 
                                    finished_key, 
                                    ssl::sum_hash(transcript_));
        std::string verify_data_base64 = codec::base64_encode(finished->verify_data);
        PUMP_DEBUG_LOG("server handshaker verify_data_base64: %s", verify_data_base64.c_str());

        status_ = HANDSHAKE_FINISHED_SENT;

        __send_handshake_message(msg);

        delete_handshake_message(msg);

        return true;
    }

    alert_code server_handshaker::__handle_certificate_tls13(handshake_message *msg) {
        if (status_ != HANDSHAKE_FINISHED_SENT) {
            return ALERT_INTERNAL_ERROR;
        }

        certificate_tls13_message *cert_tls13 = (certificate_tls13_message*)msg->msg;
        PUMP_ASSERT(cert_tls13);

        if (!cert_tls13->certificates.empty()) {
            if (!certificate_load(cert_tls13->certificates, session_.peer_certs)) {
                return ALERT_ILLEGAL_PARAMETER;
            }

            if (!ssl::verify_x509_certificates(session_.peer_certs)) {
                return ALERT_BAD_CERTIFICATE;
            }

            if (!cert_tls13->scts.empty()) {
                session_.scts = cert_tls13->scts;
            }

            
        }
    

        return ALERT_NONE;
    }

    std::string server_handshaker::__reset_transcript() {
        PUMP_ASSERT(transcript_);
        std::string hash = ssl::sum_hash(transcript_);
        ssl::free_hash_context(transcript_);
        transcript_ = ssl::create_hash_context(session_.suite_param.algo);
        PUMP_ASSERT(transcript_);
        return std::forward<std::string>(hash);
    }

    void server_handshaker::__write_transcript(const std::string &data) {
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