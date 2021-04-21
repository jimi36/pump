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
#include "pump/protocol/quic/tls/types.h"
#include "pump/protocol/quic/tls/utils.h"
#include "pump/protocol/quic/tls/server.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    server_handshaker::server_handshaker()
      : status_(HANDSHAKE_INIT),
        hello_(nullptr),
        client_hello_(nullptr),
        transcript_(nullptr) {
        init_connection_session(&session_);
    }

    server_handshaker::~server_handshaker() {
        if (hello_) {
            delete_handshake_message(hello_);
        }
        if (client_hello_) {
            object_delete(client_hello_);
        }
        reset_connection_session(&session_);
    }

    bool server_handshaker::handshake(const config &cfg) {
        if (status_ != HANDSHAKE_INIT) {
            return false;
        }

        session_.alpn = cfg.application_protocol;
        session_.server_name = cfg.server_name;

        // Load certificate.
        ssl::x509_certificate *cert = nullptr;
        if (cfg.cert_pem.empty()) {
            cert = ssl::generate_x509_certificate(ssl::TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256);
        } else {
            cert = ssl::load_x509_certificate_by_pem(cfg.cert_pem, cfg.key_pem);
        }
        if (cert == nullptr) {
            return false;
        }
        session_.certs.push_back(cert);

        return true;
    }

    alert_code server_handshaker::handshake(handshake_message *msg) {
        alert_code code = ALERT_OK;
        switch (msg->type)
        {
        case TLS_MSG_CLIENT_HELLO:
            PUMP_DEBUG_LOG("server_handshaker handle client hello message");
            code = __handle_client_hello(msg);
            break;
        case TLS_MSG_CERTIFICATE:
            PUMP_DEBUG_LOG("server_handshaker handle certificate tls13 message");
            code = __handle_certificate_tls13(msg);
            break;
        case TLS_MSG_CERTIFICATE_VERIFY:
            PUMP_DEBUG_LOG("server_handshaker handle certificate verify message");
            code = __handle_certificate_verify(msg);
            break;
        case TLS_MSG_FINISHED:
            PUMP_DEBUG_LOG("server_handshaker handle finished message");
            code = __handle_finished(msg);
            break;
        default:
            PUMP_DEBUG_LOG("server_handshaker handle unknown message");
            code = ALERT_UNEXPECTED_MESSGAE;
            break;
        }
        return code;
    }

    alert_code server_handshaker::__handle_client_hello(handshake_message *msg) {
        if (status_ != HANDSHAKE_INIT && 
            status_ != HANDSHAKE_HELLO_REQUEST_SEND) {
            return ALERT_UNEXPECTED_MESSGAE;
        }

        auto client_hello = (client_hello_message*)msg->raw_msg;
        PUMP_ASSERT(client_hello);

        if (client_hello->legacy_version != TLS_VSERVER_12) {
            return ALERT_ILLEGAL_PARAMETER;
        }
        
        version_type version13 = TLS_VSERVER_13;
        if (!is_contains(client_hello->supported_versions, version13)) {
            return ALERT_PROTOCOL_VERSION;
        }

        if (client_hello->compression_methods.size() != 1 || 
            client_hello->compression_methods[0] != TLS_COMPRESSION_METHOD_NONE) {
            return ALERT_ILLEGAL_PARAMETER;
        }

        if (!client_hello->renegotiation_info.empty()) {
            return ALERT_HANDSHAKE_FAILURE;
        }

        if (client_hello->signature_schemes.empty()) {
            return ALERT_MISSING_EXTENSION;
        }

        if (!is_contains(client_hello->alpns, session_.alpn)) {
            return ALERT_ILLEGAL_PARAMETER;
        }
        
        // Load cipher suite.
        if (session_.cipher_suite_ctx) {
            delete_cipher_suite_context(session_.cipher_suite_ctx);
            session_.cipher_suite_ctx = nullptr;
        }
        cipher_suite_type selected_cipher_suite = TLS_CIPHER_SUITE_UNKNOWN;
        for (auto cs : supported_cipher_suites) {
            if (is_contains(client_hello->cipher_suites, cs)) {
                session_.cipher_suite_ctx = new_cipher_suite_context(cs);
                if (session_.cipher_suite_ctx == nullptr) {
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
        ssl::curve_group_type selected_group = ssl::TLS_CURVE_UNKNOWN;
        for (auto supported_group : supported_curve_groups) {
            for (auto &ks : client_hello->key_shares) {
                if (ks.group == supported_group) {
                    selected_group = ks.group;
                    client_ks = &ks;
                    break;
                }
            }
            if (client_ks != nullptr) {
                break;
            }
            if (selected_group == ssl::TLS_CURVE_UNKNOWN && 
                is_contains(client_hello->supported_groups, supported_group)) {
                selected_group = supported_group;
            }
        }
        if (selected_group == ssl::TLS_CURVE_UNKNOWN) {
            return ALERT_HANDSHAKE_FAILURE;
        }

        client_hello_ = client_hello;
        msg->raw_msg = nullptr;

        __write_transcript(pack_handshake_message(msg));

        if (client_ks == nullptr) {
            return __send_hello_retry_request(selected_cipher_suite, selected_group);
        }

        status_ = HANDSHAKE_CLIENT_HELLO_RECV;

        // Check certificate signature scheme.
        PUMP_ASSERT(!session_.certs.empty());
        ssl::signature_scheme sign_scheme = ssl::get_x509_signature_scheme(session_.certs[0]);
        if (sign_scheme == ssl::TLS_SIGN_SCHE_UNKNOWN) {
            return ALERT_INTERNAL_ERROR;
        }
        if (!is_contains(client_hello->signature_schemes, sign_scheme)) {
            return ALERT_HANDSHAKE_FAILURE;
        }

        session_.ecdhe_ctx = ssl::new_ecdhe_context(selected_group);
        if (session_.ecdhe_ctx == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }

        if (client_hello->server_name != session_.server_name) {
            return ALERT_HANDSHAKE_FAILURE;
        }

        alert_code code = ALERT_OK;
        if ((code = __send_server_hello()) != ALERT_OK) {
            return code;
        }
        if ((code = __send_encrypted_extensions()) != ALERT_OK) {
            return code;
        }
        // TODO: Dont need client certificate?
        if ((code = __send_certificate_request()) != ALERT_OK) {
            return code;
        }
        if ((code = __send_certificate_tls13()) != ALERT_OK) {
            return code;
        }
        if ((code = __send_certificate_verify()) != ALERT_OK) {
            return code;
        }
        if ((code = __send_finished()) != ALERT_OK) {
            return code;
        }

        return ALERT_OK;
    }

    alert_code server_handshaker::__send_hello_retry_request(
        cipher_suite_type cipher_suite,
        ssl::curve_group_type curve_group) {
        if (status_ != HANDSHAKE_INIT) {
            return ALERT_UNEXPECTED_MESSGAE;
        }
        status_ = HANDSHAKE_HELLO_REQUEST_SEND;

        auto msg = new_handshake_message(TLS_MSG_SERVER_HELLO);
        if (msg == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }
        toolkit::defer cleanup([&](){
            delete_handshake_message(msg);
        });
        auto server_hello = (server_hello_message*)msg->raw_msg;

        server_hello->legacy_version = TLS_VSERVER_12;

        server_hello->supported_version = TLS_VSERVER_13;

        server_hello->session_id = client_hello_->session_id;

        server_hello->compression_method = TLS_COMPRESSION_METHOD_NONE;

        server_hello->selected_group = curve_group;

        server_hello->cipher_suite = cipher_suite;

        memcpy(server_hello->random, hello_retry_request_random, 32);
  
        __write_transcript(pack_msg_hash_message(__reset_transcript()));

        PUMP_DEBUG_LOG("server_handshaker send hello request message");
        __send_handshake_message(msg);

        return ALERT_OK;
    }

    alert_code server_handshaker::__send_server_hello() {
        if (status_ != HANDSHAKE_CLIENT_HELLO_RECV) {
            return ALERT_INTERNAL_ERROR;
        }
        status_ = HANDSHAKE_SERVER_HELLO_SEND;

        hello_ = new_handshake_message(TLS_MSG_SERVER_HELLO);
        if (hello_ == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }
        auto server_hello = (server_hello_message*)hello_->raw_msg;

        server_hello->legacy_version = TLS_VSERVER_12;

        server_hello->supported_version = TLS_VSERVER_13;

        server_hello->compression_method = TLS_COMPRESSION_METHOD_NONE;

        server_hello->cipher_suite = session_.cipher_suite_ctx->type;

        server_hello->session_id = client_hello_->session_id;

        server_hello->has_selected_key_share = true;
        server_hello->selected_key_share.group = session_.ecdhe_ctx->group;
        server_hello->selected_key_share.data = session_.ecdhe_ctx->pubkey;

        std::default_random_engine random;
        for (int32_t i = 0; i < (int32_t)sizeof(server_hello->random); i++) {
            server_hello->random[i]= random();
        }
   
        __write_transcript(pack_handshake_message(hello_));

        {
            auto secret = cipher_suite_device_secret(
                            session_.cipher_suite_ctx, 
                            cipher_suite_extract(session_.cipher_suite_ctx, "", ""), 
                            "derived", 
                            nullptr);
            auto shared_key = ssl::gen_ecdhe_shared_key(
                                session_.ecdhe_ctx, 
                                client_hello_->key_shares[0].data);
            session_.handshake_secret = cipher_suite_extract(session_.cipher_suite_ctx, secret, shared_key);
            //auto handshake_secret_base64 = codec::base64_encode(session_.handshake_secret);
            //PUMP_DEBUG_LOG("server handshaker handshake_secret_base64: %s", handshake_secret_base64.c_str());
        }

        session_.client_secret = cipher_suite_device_secret(
                                    session_.cipher_suite_ctx, 
                                    session_.handshake_secret,
                                    CLIENT_HANDSHAKE_TRAFFIC_LABEL, 
                                    transcript_);
        //auto client_secret_base64 = codec::base64_encode(session_.client_secret);
        //PUMP_DEBUG_LOG("server handshaker client_secret_base64: %s", client_secret_base64.c_str());

        session_.server_secret = cipher_suite_device_secret(
                                    session_.cipher_suite_ctx, 
                                    session_.handshake_secret,
                                    SERVER_HANDSHAKE_TRAFFIC_LABEL, 
                                    transcript_);
        //auto server_secret_base64 = codec::base64_encode(session_.server_secret);
        //PUMP_DEBUG_LOG("server handshaker server_secret_base64: %s", server_secret_base64.c_str());

        {
            auto secret = cipher_suite_device_secret(
                            session_.cipher_suite_ctx, 
                            session_.handshake_secret, 
                            "derived", 
                            nullptr);
            session_.master_secret = cipher_suite_extract(session_.cipher_suite_ctx, secret, "");
            //auto master_secret_base64 = codec::base64_encode(session_.master_secret);
            //PUMP_DEBUG_LOG("server handshaker master_secret_base64: %s", master_secret_base64.c_str());
        }

        PUMP_DEBUG_LOG("server_handshaker send server hello message");
        __send_handshake_message(hello_, false);

        return ALERT_OK;
    }

    alert_code server_handshaker::__send_encrypted_extensions() {
        if (status_ != HANDSHAKE_SERVER_HELLO_SEND) {
            return ALERT_INTERNAL_ERROR;
        }
        status_ = HANDSHAKE_ENCRYPTED_EXTENSIONS_SEND;

        auto msg = new_handshake_message(TLS_MSG_ENCRYPTED_EXTENSIONS);
        if (msg == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }
        toolkit::defer cleanup([&](){
            delete_handshake_message(msg);
        });
        auto encrypted_extensions = (encrypted_extensions_message*)msg->raw_msg;

        encrypted_extensions->is_support_early_data = false;

        encrypted_extensions->alpn = session_.alpn;

        PUMP_DEBUG_LOG("server_handshaker send encrypted extensions message");
        __send_handshake_message(msg);

        return ALERT_OK;
    }

    alert_code server_handshaker::__send_certificate_request() {
        if (status_ != HANDSHAKE_ENCRYPTED_EXTENSIONS_SEND) {
            return ALERT_INTERNAL_ERROR;
        }
        status_ = HANDSHAKE_CARTIFICATE_REQUEST_SEND;

        auto msg = new_handshake_message(TLS_MSG_CERTIFICATE_REQUEST);
        if (msg == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }
        toolkit::defer cleanup([&](){
            delete_handshake_message(msg);
        });
        auto cert_request = (certificate_req_tls13_message*)msg->raw_msg;

        cert_request->is_support_scts = true;

        cert_request->is_support_ocsp_stapling = true;

        cert_request->supported_signature_schemes = supported_signature_schemes;

        // TODO: How to fill it?
        //cert_request->certificate_authorities = ??;

        PUMP_DEBUG_LOG("server_handshaker send certificate request tls13 message");
        __send_handshake_message(msg);

        return ALERT_OK;
    }

    alert_code server_handshaker::__send_certificate_tls13() {
        if (status_ != HANDSHAKE_ENCRYPTED_EXTENSIONS_SEND &&
            status_ != HANDSHAKE_CARTIFICATE_REQUEST_SEND) {
            return ALERT_INTERNAL_ERROR;
        }
        status_ = HANDSHAKE_CARTIFICATE_SEND;

        auto msg = new_handshake_message(TLS_MSG_CERTIFICATE);
        if (msg == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }
        toolkit::defer cleanup([&](){
            delete_handshake_message(msg);
        });
        auto cert_tls13 = (certificate_tls13_message*)msg->raw_msg;

        PUMP_ASSERT(!session_.certs.empty());
        for (auto cert : session_.certs) {
            cert_tls13->certificates.push_back(ssl::to_x509_certificate_raw(cert));
        }

        // TODO: Support scts? Default not.
        //cert_tls13->is_support_scts = false;
        PUMP_DEBUG_CHECK(ssl::get_x509_scts(session_.certs[0], cert_tls13->scts));
        if (client_hello_->is_support_scts && !cert_tls13->scts.empty()) {
            cert_tls13->is_support_scts = true;
        }

        // TODO: Support ocsp staple? Default not.
        //cert_tls13->is_support_ocsp_stapling = false;
        if (client_hello_->is_support_ocsp_stapling) {
            PUMP_DEBUG_LOG("tls client hello support ocsp staple");
        }

        PUMP_DEBUG_LOG("server_handshaker send certificate tls13 message");
        __send_handshake_message(msg);

        return ALERT_OK;
    }

    alert_code server_handshaker::__send_certificate_verify() {
        if (status_ != HANDSHAKE_CARTIFICATE_SEND) {
            return ALERT_INTERNAL_ERROR;
        }
        status_ = HANDSHAKE_CARTIFICATE_VERIFY_SEND;

        auto msg = new_handshake_message(TLS_MSG_CERTIFICATE_VERIFY);
        if (msg == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }
        toolkit::defer cleanup([&](){
            delete_handshake_message(msg);
        });
        auto cert_verify = (certificate_verify_message*)msg->raw_msg;

        PUMP_ASSERT(!session_.certs.empty());
        if (session_.certs.empty()) {
            return ALERT_INTERNAL_ERROR;
        }
        
        cert_verify->signature_scheme = ssl::get_x509_signature_scheme(session_.certs[0]);
        if (cert_verify->signature_scheme == ssl::TLS_SIGN_SCHE_UNKNOWN) {
            return ALERT_INTERNAL_ERROR;
        }

        auto hash_algo = transform_to_hash_algo(cert_verify->signature_scheme);
        if (hash_algo == ssl::HASH_UNKNOWN) {
            return ALERT_INTERNAL_ERROR;
        }

        auto sign_algo = transform_to_sign_algo(cert_verify->signature_scheme);
        if (sign_algo == ssl::TLS_SIGN_ALGO_UNKNOWN) {
            return ALERT_INTERNAL_ERROR;
        }

        auto signed_msg = generate_signed_message(
                        hash_algo, 
                        SERVER_SIGNATURE_CONTEXT, 
                        ssl::sum_hash(transcript_));
        
        if (!ssl::do_x509_signature(
                session_.certs[0], 
                sign_algo, 
                hash_algo, 
                signed_msg, 
                cert_verify->signature)) {
            return ALERT_INTERNAL_ERROR;
        }
        auto signed_msg_base64 = codec::base64_encode(signed_msg);
        auto signature_base64 = codec::base64_encode(cert_verify->signature);
        //PUMP_DEBUG_LOG("client handshaker verify signature sign: %d hash: %ld msg: %s signature: %s", 
        //    sign_algo,
        //    hash_algo,
        //    signed_msg_base64.c_str(),
        //    signature_base64.c_str());

        PUMP_DEBUG_LOG("server_handshaker send certificate verify message");
        __send_handshake_message(msg);

        return ALERT_OK;
    }

    alert_code server_handshaker::__send_finished() {
        if (status_ != HANDSHAKE_CARTIFICATE_SEND && 
            status_ != HANDSHAKE_CARTIFICATE_VERIFY_SEND) {
            return ALERT_INTERNAL_ERROR;
        }
        status_ = HANDSHAKE_FINISHED_SEND;

        auto msg = new_handshake_message(TLS_MSG_FINISHED);
        if (msg == nullptr) {
            return ALERT_INTERNAL_ERROR;
        }
        toolkit::defer cleanup([&](){
            delete_handshake_message(msg);
        });
        auto finished = (finished_message*)msg->raw_msg;

        auto finished_key = hkdf_expand_label(
                                session_.cipher_suite_ctx->algo, 
                                session_.server_secret, 
                                "", 
                                "finished", 
                                ssl::hash_digest_length(session_.cipher_suite_ctx->algo));
        finished->verify_data = ssl::sum_hmac(
                                    session_.cipher_suite_ctx->algo, 
                                    finished_key, 
                                    ssl::sum_hash(transcript_));
        //auto verify_data_base64 = codec::base64_encode(finished->verify_data);
        //PUMP_DEBUG_LOG("server handshaker server verify_data_base64: %s", verify_data_base64.c_str());

        __write_transcript(pack_handshake_message(msg));

        session_.traffic_secret = cipher_suite_device_secret(
                                    session_.cipher_suite_ctx, 
                                    session_.master_secret,
                                    CLIENT_APPLICATION_TRAFFIC_LABEL, 
                                    transcript_);
        //auto traffic_secret_base64 = codec::base64_encode(session_.traffic_secret);
        //PUMP_DEBUG_LOG("server handshaker traffic_secret_base64: %s", traffic_secret_base64.c_str());

        session_.server_secret = cipher_suite_device_secret(
                                    session_.cipher_suite_ctx, 
                                    session_.master_secret,
                                    SERVER_APPLICATION_TRAFFIC_LABEL, 
                                    transcript_);
        //auto server_secret_base64 = codec::base64_encode(session_.server_secret);
        //PUMP_DEBUG_LOG("server handshaker server_secret_base64: %s", server_secret_base64.c_str());

        // https://tools.ietf.org/html/rfc8446#section-7.5
        session_.export_master_secret = cipher_suite_device_secret(
                                            session_.cipher_suite_ctx, 
                                            session_.master_secret, 
                                            EXPORTER_LABEL, 
                                            transcript_);
        //auto export_master_secret_base64 = codec::base64_encode(session_.export_master_secret);
        //PUMP_DEBUG_LOG("server handshaker export_master_secret_base64: %s", export_master_secret_base64.c_str());

        PUMP_DEBUG_LOG("server_handshaker send finished message");
        __send_handshake_message(msg, false);

        return ALERT_OK;
    }

    alert_code server_handshaker::__handle_certificate_tls13(handshake_message *msg) {
        if (status_ != HANDSHAKE_FINISHED_SEND) {
            return ALERT_INTERNAL_ERROR;
        }
        status_ = HANDSHAKE_CARTIFICATE_RECV;

        auto cert_tls13 = (certificate_tls13_message*)msg->raw_msg;
        PUMP_ASSERT(cert_tls13);

        if (!cert_tls13->certificates.empty()) {
            for (auto &certificate : cert_tls13->certificates) {
                auto cert = ssl::load_x509_certificate_by_raw(certificate, "");
                if (cert == nullptr) {
                    return ALERT_ILLEGAL_PARAMETER;
                }
                session_.peer_certs.push_back(cert);
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
        }

        __write_transcript(pack_handshake_message(msg));

        return ALERT_OK;
    }

    alert_code server_handshaker::__handle_certificate_verify(handshake_message *msg) {
        if (status_ != HANDSHAKE_CARTIFICATE_RECV) {
            return ALERT_INTERNAL_ERROR;
        }
        status_ = HANDSHAKE_CARTIFICATE_VERIFY_RECV;

        if (session_.peer_certs.empty()) {
            return ALERT_HANDSHAKE_FAILURE;
        }

        auto cert_verify = (certificate_verify_message*)msg->raw_msg;
        PUMP_ASSERT(cert_verify);

        if (!is_contains(supported_signature_schemes, cert_verify->signature_scheme)) {
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

        auto signed_msg = generate_signed_message(
                            hash_algo, 
                            SERVER_SIGNATURE_CONTEXT, 
                            ssl::sum_hash(transcript_));
        if (!ssl::verify_x509_signature(
                session_.certs[0], 
                sign_algo, 
                hash_algo, 
                signed_msg, 
                cert_verify->signature)) {
            return ALERT_DECRYPT_ERROR;
        }

        __write_transcript(pack_handshake_message(msg));

        return ALERT_OK;
    }

    alert_code server_handshaker::__handle_finished(handshake_message *msg) {
        if (status_ != HANDSHAKE_CARTIFICATE_RECV &&
            status_ != HANDSHAKE_CARTIFICATE_VERIFY_RECV) {
            return ALERT_UNEXPECTED_MESSGAE;
        }
        status_ = HANDSHAKE_FINISHED_RECV;

        auto finished = (finished_message*)msg->raw_msg;
        PUMP_ASSERT(finished);

        // https://tools.ietf.org/html/rfc8446#section-4.4.4
        // https://tools.ietf.org/html/rfc8446#section-4.2.11.2
        auto finished_key = hkdf_expand_label(
                                session_.cipher_suite_ctx->algo, 
                                session_.client_secret, 
                                "", 
                                "finished", 
                                ssl::hash_digest_length(session_.cipher_suite_ctx->algo));
        auto verify_data = ssl::sum_hmac(
                            session_.cipher_suite_ctx->algo, 
                            finished_key, 
                            ssl::sum_hash(transcript_));
        //auto verify_data_base64 = codec::base64_encode(verify_data);
        //PUMP_DEBUG_LOG("server handshaker client verify_data_base64: %s", verify_data_base64.c_str());
        if (verify_data != finished->verify_data) {
            return ALERT_DECRYPT_ERROR;
        }

        __write_transcript(pack_handshake_message(msg));

        status_ = HANDSHAKE_SUCCESS;

        if (finished_callback_) {
            finished_callback_(session_);
        }

        return ALERT_OK;
    }

    std::string server_handshaker::__reset_transcript() {
        PUMP_ASSERT(transcript_);
        std::string hash = ssl::sum_hash(transcript_);
        ssl::free_hash_context(transcript_);
        transcript_ = ssl::create_hash_context(session_.cipher_suite_ctx->algo);
        PUMP_ASSERT(transcript_);
        return std::forward<std::string>(hash);
    }

    void server_handshaker::__write_transcript(const std::string &data) {
        if (transcript_ == nullptr) {
            transcript_ = ssl::create_hash_context(session_.cipher_suite_ctx->algo);
            PUMP_ASSERT(transcript_);
        }
        PUMP_DEBUG_CHECK(ssl::update_hash(transcript_, data));
    }

} // namespace tls
} // namespace quic
} // namespace protocol
} // namespace pump