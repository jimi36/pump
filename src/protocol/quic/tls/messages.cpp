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

#include "pump/memory.h"
#include "pump/protocol/quic/tls/utils.h"
#include "pump/protocol/quic/tls/messages.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {
    
    handshake_message* new_handshake_message(message_type type) {
        auto msg = object_create<handshake_message>();
        if (msg == nullptr) {
            return nullptr;
        }
        msg->type = type;
        msg->raw_msg = nullptr;

#define CASE_NEW_MESSAGE(msg_type, new_msg) \
    case msg_type: \
        msg->raw_msg = new_msg(); break;
        switch (type) {
        CASE_NEW_MESSAGE(TLS_MSG_HELLO_REQUEST, new_hello_request)
        CASE_NEW_MESSAGE(TLS_MSG_CLIENT_HELLO, new_client_hello)
        CASE_NEW_MESSAGE(TLS_MSG_SERVER_HELLO, new_server_hello)
        CASE_NEW_MESSAGE(TLS_MSG_NEW_SESSION_TICKET, new_new_session_ticket_tls13)
        CASE_NEW_MESSAGE(TLS_MSG_END_OF_EARLY_DATA, new_end_early_data)
        CASE_NEW_MESSAGE(TLS_MSG_ENCRYPTED_EXTENSIONS, new_encrypted_extensions)
        CASE_NEW_MESSAGE(TLS_MSG_CERTIFICATE, new_certificate_tls13)
        CASE_NEW_MESSAGE(TLS_MSG_SERVER_KEY_EXCHANGE, new_server_key_exchange)
        CASE_NEW_MESSAGE(TLS_MSG_CERTIFICATE_REQUEST, new_certificate_request_tls13)
        CASE_NEW_MESSAGE(TLS_MSG_SERVER_HELLO_DONE, new_server_hello_done)
        CASE_NEW_MESSAGE(TLS_MSG_CERTIFICATE_VERIFY, new_certificate_verify)
        CASE_NEW_MESSAGE(TLS_MSG_CLIENT_KEY_EXCHANGE, new_client_key_exchange)
        CASE_NEW_MESSAGE(TLS_MSG_FINISHED, new_finished)
        CASE_NEW_MESSAGE(TLS_MSG_CERTIFICATE_STATUS, new_certificate_status)
        CASE_NEW_MESSAGE(TLS_MSG_KEY_UPDATE, new_key_update)
        }
#undef CASE_NEW_MESSAGE

        if (msg->raw_msg == nullptr) {
            object_delete(msg);
            return nullptr;
        }

        return msg;
    }

    void delete_handshake_message(handshake_message *msg) {
        if (msg == nullptr) {
            return;
        }

#define CASE_DELETE_MESSAGE(msg_type, msg_class) \
    case msg_type: \
        object_delete((msg_class*)msg->raw_msg); break;
        if (msg->raw_msg != nullptr) {
            switch (msg->type) {
            CASE_DELETE_MESSAGE(TLS_MSG_HELLO_REQUEST, hello_request_message)
            CASE_DELETE_MESSAGE(TLS_MSG_CLIENT_HELLO, client_hello_message)
            CASE_DELETE_MESSAGE(TLS_MSG_SERVER_HELLO, server_hello_message)
            CASE_DELETE_MESSAGE(TLS_MSG_NEW_SESSION_TICKET, new_session_ticket_tls13_message)
            CASE_DELETE_MESSAGE(TLS_MSG_END_OF_EARLY_DATA, end_early_data_message)
            CASE_DELETE_MESSAGE(TLS_MSG_ENCRYPTED_EXTENSIONS, encrypted_extensions_message)
            CASE_DELETE_MESSAGE(TLS_MSG_CERTIFICATE, certificate_tls13_message)
            CASE_DELETE_MESSAGE(TLS_MSG_SERVER_KEY_EXCHANGE, server_key_exchange_message)
            CASE_DELETE_MESSAGE(TLS_MSG_CERTIFICATE_REQUEST, certificate_request_tls13_message)
            CASE_DELETE_MESSAGE(TLS_MSG_SERVER_HELLO_DONE, server_hello_done_message)
            CASE_DELETE_MESSAGE(TLS_MSG_CERTIFICATE_VERIFY, certificate_verify_message)
            CASE_DELETE_MESSAGE(TLS_MSG_CLIENT_KEY_EXCHANGE, client_key_exchange_message)
            CASE_DELETE_MESSAGE(TLS_MSG_FINISHED, finished_message)
            CASE_DELETE_MESSAGE(TLS_MSG_CERTIFICATE_STATUS, certificate_status_message)
            CASE_DELETE_MESSAGE(TLS_MSG_KEY_UPDATE, key_update_message)
            }
        }
#undef CASE_DELETE_MESSAGE

        object_delete(msg);
    }

    const std::string& pack_handshake_message(handshake_message *msg) {
        if (!msg->packed_data.empty()) {
            return msg->packed_data;
        }

        uint8_t buffer[4096];
        int32_t packed_data_size = -1;
        
#define CASE_PACK_MESSAGE(msg_type, pack) \
    case msg_type: \
    { \
        packed_data_size = pack((c_void_ptr)msg->raw_msg, buffer, sizeof(buffer)); \
        break; \
    }
        switch (msg->type) {
        CASE_PACK_MESSAGE(TLS_MSG_HELLO_REQUEST, pack_hello_request)
        CASE_PACK_MESSAGE(TLS_MSG_CLIENT_HELLO, pack_client_hello)
        CASE_PACK_MESSAGE(TLS_MSG_SERVER_HELLO, pack_server_hello)
        CASE_PACK_MESSAGE(TLS_MSG_NEW_SESSION_TICKET, pack_new_session_ticket_tls13)
        CASE_PACK_MESSAGE(TLS_MSG_END_OF_EARLY_DATA, pack_end_early_data)
        CASE_PACK_MESSAGE(TLS_MSG_ENCRYPTED_EXTENSIONS, pack_encrypted_extensions)
        CASE_PACK_MESSAGE(TLS_MSG_CERTIFICATE, pack_certificate_tls13)
        CASE_PACK_MESSAGE(TLS_MSG_SERVER_KEY_EXCHANGE, pack_server_key_exchange)
        CASE_PACK_MESSAGE(TLS_MSG_CERTIFICATE_REQUEST, pack_certificate_request_tls13)
        CASE_PACK_MESSAGE(TLS_MSG_SERVER_HELLO_DONE, pack_server_hello_done)
        CASE_PACK_MESSAGE(TLS_MSG_CERTIFICATE_VERIFY, pack_certificate_verify)
        CASE_PACK_MESSAGE(TLS_MSG_CLIENT_KEY_EXCHANGE, pack_client_key_exchange)
        CASE_PACK_MESSAGE(TLS_MSG_FINISHED, pack_finished)
        CASE_PACK_MESSAGE(TLS_MSG_CERTIFICATE_STATUS, pack_certificate_status)
        CASE_PACK_MESSAGE(TLS_MSG_KEY_UPDATE, pack_key_update)
        }
#undef PACK_MESSAGE

        if (packed_data_size > 0) {
            msg->packed_data.assign((char*)buffer, packed_data_size);
        }

        return msg->packed_data;
    }

    int32_t unpack_handshake_message(
        const uint8_t *buf, 
        int32_t size, 
        handshake_message *msg) {
        if (msg == nullptr || msg->raw_msg == nullptr) {
            return -1; 
        }

        int32_t unpack_size = -1;

#define CASE_UNPACK_MESSAGE(msg_type, unpack) \
    case msg_type: \
    { \
        unpack_size = unpack(buf, size, msg->raw_msg); \
        break; \
    }
        switch (buf[0]) {
        CASE_UNPACK_MESSAGE(TLS_MSG_HELLO_REQUEST, unpack_hello_request)
        CASE_UNPACK_MESSAGE(TLS_MSG_CLIENT_HELLO, unpack_client_hello)
        CASE_UNPACK_MESSAGE(TLS_MSG_SERVER_HELLO, unpack_server_hello)
        CASE_UNPACK_MESSAGE(TLS_MSG_NEW_SESSION_TICKET, unpack_new_session_ticket_tls13)
        CASE_UNPACK_MESSAGE(TLS_MSG_END_OF_EARLY_DATA, unpack_end_early_data)
        CASE_UNPACK_MESSAGE(TLS_MSG_ENCRYPTED_EXTENSIONS, unpack_encrypted_extensions)
        CASE_UNPACK_MESSAGE(TLS_MSG_CERTIFICATE, unpack_certificate_tls13)
        CASE_UNPACK_MESSAGE(TLS_MSG_SERVER_KEY_EXCHANGE, unpack_server_key_exchange)
        CASE_UNPACK_MESSAGE(TLS_MSG_CERTIFICATE_REQUEST, unpack_certificate_request_tls13)
        CASE_UNPACK_MESSAGE(TLS_MSG_SERVER_HELLO_DONE, unpack_server_hello_done)
        CASE_UNPACK_MESSAGE(TLS_MSG_CERTIFICATE_VERIFY, unpack_certificate_verify)
        CASE_UNPACK_MESSAGE(TLS_MSG_CLIENT_KEY_EXCHANGE, unpack_client_key_exchange)
        CASE_UNPACK_MESSAGE(TLS_MSG_FINISHED, unpack_finished)
        CASE_UNPACK_MESSAGE(TLS_MSG_CERTIFICATE_STATUS, unpack_certificate_status)
        CASE_UNPACK_MESSAGE(TLS_MSG_KEY_UPDATE, unpack_key_update)
        }
#undef CASE_UNPACK_MESSAGE

        if (unpack_size > 0) {
            msg->packed_data.assign((char*)buf, unpack_size);
        }

        return unpack_size;
    }

#define PACK_AND_RETURN_ERR(pack) \
    p = pack; if (!p) { return -1; } void(0)

#define UNPACK_AND_RETURN_ERR(unpack) \
    p = unpack; if (!p) { return -1; } void(0)

    hello_request_message* new_hello_request() {
        return object_create<hello_request_message>();
    }

    int32_t pack_hello_request(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_HELLO_REQUEST));

        // Pack payload length.
        PACK_AND_RETURN_ERR(pack_uint24(p, end, 0));

        return int32_t(p - buf);
    }

    int32_t unpack_hello_request(const uint8_t *buf, int32_t size, void_ptr msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_HELLO_REQUEST) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        return int32_t(p - buf);
    }

    client_hello_message* new_client_hello() {
        auto msg = object_create<client_hello_message>();
        if (msg) {
            msg->legacy_version = TLS_VERSION_UNKNOWN;
            msg->is_support_ocsp_stapling = false;
            msg->is_support_session_ticket = false;
            msg->is_support_renegotiation_info = false;
            msg->is_support_scts = false;
            msg->is_support_early_data = false;
        }
        return msg;
    }

    int32_t pack_client_hello(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const client_hello_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_CLIENT_HELLO));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Pack client tls version with 2 bytes.
        PACK_AND_RETURN_ERR(pack_uint16(p, end, raw->legacy_version));

        // Pack random with 32 bytes.
        PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->random, 32));

        // Pack session id.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, (uint8_t)raw->session_id.size()));
        if (!raw->session_id.empty()) {
            PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->session_id));
        }

        // Pack cipher suites.
        PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(raw->cipher_suites.size() * 2)));
        for (auto cs : raw->cipher_suites) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, cs));
        }

        // Pack compression methods.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, (uint8_t)raw->compression_methods.size()));
        for (auto method : raw->compression_methods) {
            PACK_AND_RETURN_ERR(pack_uint8(p, end, method));
        }
        
        // Skip to pack extensions length with 2 bytes.
        uint8_t *extension_len = p; p += 2;

        // Pack server name extenion.
        if (!raw->server_name.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SERVER_NAME));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(2 + 1 + 2 + raw->server_name.size())));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(1 + 2 + raw->server_name.size())));
            PACK_AND_RETURN_ERR(pack_uint8(p, end, 0)); // name_type = host_name
            PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)raw->server_name.size())); // server name length
            PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->server_name));
        }

        // Pack ocsp extenion.
        if (raw->is_support_ocsp_stapling) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_STATUS_REQUEST));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 5));
            PACK_AND_RETURN_ERR(pack_uint8(p, end, 1)); // status_type = ocsp
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 0)); // empty responder_id_list
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 0)); // empty request_extensions
        }

        // Pack supported curve groups extenion.
        if (!raw->supported_groups.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SUPPORTED_GROUPS));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(2 + raw->supported_groups.size() * 2)));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(raw->supported_groups.size() * 2)));
            for (auto group : raw->supported_groups) {
                PACK_AND_RETURN_ERR(pack_uint16(p, end, group));
            }
        }

        // Pack supported point formats extenion.
        if (!raw->supported_points.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SUPPORTED_POINTS));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(1 + raw->supported_points.size())));
            PACK_AND_RETURN_ERR(pack_uint8(p, end, (uint8_t)raw->supported_points.size()));
            for (auto point : raw->supported_points) {
                PACK_AND_RETURN_ERR(pack_uint8(p, end, point));
            }
        }

        // Pack session ticket extenion.
        if (raw->is_support_session_ticket) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SESSION_TICKET));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)raw->session_ticket.size()));
            PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->session_ticket));
        }

        // Pack supported signature algorithms extenion.
        if (!raw->supported_signature_schemes.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SIGNATURE_ALGORITHMS));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(2 + raw->supported_signature_schemes.size() * 2)));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(raw->supported_signature_schemes.size() * 2)));
            for (auto scheme : raw->supported_signature_schemes) {
                PACK_AND_RETURN_ERR(pack_uint16(p, end, scheme));
            }
        }

        // Pack supported signature algorithms certs extenion.
        if (!raw->supported_signature_scheme_certs.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(2 + raw->supported_signature_scheme_certs.size() * 2)));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(raw->supported_signature_scheme_certs.size() * 2)));
            for (auto scheme_cert : raw->supported_signature_scheme_certs) {
                PACK_AND_RETURN_ERR(pack_uint16(p, end, scheme_cert));
            }
        }

        // Pack renegotiation info extenion.
        if (raw->is_support_renegotiation_info) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_RENEGOTIATION_INFO));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(1 + raw->renegotiation_info.size())));
            PACK_AND_RETURN_ERR(pack_uint8(p, end, (uint8_t)raw->renegotiation_info.size()));
            PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->renegotiation_info));
        }

        // Pack application layer protocol negotiation extenion.
        if (!raw->alpns.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_ALPN));
            uint8_t *len = p; p += 2 * 2;
            for (auto &alpn : raw->alpns) {
                PACK_AND_RETURN_ERR(pack_uint8(p, end, (uint8_t)alpn.size()));
                PACK_AND_RETURN_ERR(pack_bytes(p, end, alpn));
            }
            pack_uint16(len, p, uint16_t(p - len - 2));
            pack_uint16(len + 2, p, uint16_t(p - len - 4));
        }

        // Pack signed certificate timestamp extenion.
        if (raw->is_support_scts) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SCT));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 0)); // empty extension_data
        }

        // Pack supported versions extenion.
        if (!raw->supported_versions.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SUPPORTED_VERSIONS));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(1 + raw->supported_versions.size() * 2)));
            PACK_AND_RETURN_ERR(pack_uint8(p, end, uint8_t(raw->supported_versions.size() * 2)));
            for (auto version : raw->supported_versions) {
                PACK_AND_RETURN_ERR(pack_uint16(p, end, version));
            }
        }

        // Pack cookie extenion.
        if (!raw->cookie.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_COOKIE));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(2 + raw->cookie.size())));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)raw->cookie.size()));
            PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->cookie));
        }

        // Pack key shares extenion.
        if (!raw->key_shares.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_KEY_SHARE));
            uint8_t *len = p; p += 2 * 2;
            for (auto &ks : raw->key_shares) {
                PACK_AND_RETURN_ERR(pack_uint16(p, end, ks.group));
                PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)ks.data.size()));
                PACK_AND_RETURN_ERR(pack_bytes(p, end, ks.data));
            }
            pack_uint16(len, p, uint16_t(p - len - 2));
            pack_uint16(len + 2, p, uint16_t(p - len - 4));
        }

        // Pack early data extenion.
        if (raw->is_support_early_data) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_EARLY_DATA));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 0)); // empty extension_data
        }

        // Pack psk modes extenion.
        if (!raw->psk_modes.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_PSK_MODES));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(1 + raw->psk_modes.size())));
            PACK_AND_RETURN_ERR(pack_uint8(p, end, (uint8_t)raw->psk_modes.size()));
            for (auto mode : raw->psk_modes) {
                PACK_AND_RETURN_ERR(pack_uint8(p, end, mode));
            }
        }

        // Pack additional extensions.
        for (auto &extension : raw->additional_extensions) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, extension.type));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)extension.data.size()));
            PACK_AND_RETURN_ERR(pack_bytes(p, end, extension.data));
        }

        // Pack psk identities extenion.
        if (!raw->psk_identities.empty()) { // Must serizlize the extenion at last.
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_PRE_SHARED_KEY));
            uint8_t *len1 = p; p += 2;
            {
                uint8_t *len2 = p; p += 2;
                for (auto &id : raw->psk_identities) {
                    PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)id.identity.size()));
                    PACK_AND_RETURN_ERR(pack_bytes(p, end, id.identity));
                    PACK_AND_RETURN_ERR(pack_uint32(p, end, id.obfuscated_ticket_age));
                }
                pack_uint16(len2, p, uint16_t(p - len2 - 2));
            }
            {
                uint8_t *len2 = p; p += 2;
                for (auto &binder : raw->psk_binders) {
                    PACK_AND_RETURN_ERR(pack_uint8(p, end, (uint8_t)binder.size()));
                    PACK_AND_RETURN_ERR(pack_bytes(p, end, binder));
                }
                pack_uint16(len2, p, uint16_t(p - len2 - 2));
            }
            pack_uint16(len1, p, uint16_t(p - len1 - 2));
        }

        // Pack extensions length.
        pack_uint16(extension_len, p, uint16_t(p - extension_len - 2));

        // Pack payload length.
        pack_uint24(payload_len, p, uint16_t(p - payload_len - 3));

        return int32_t(p - buf);
    }

    int32_t unpack_client_hello(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (client_hello_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CLIENT_HELLO) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        // Unpack client tls version.
        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, raw->legacy_version));

        // Unpack random with 32 bytes.
        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->random, 32));

        // Unpack session id.
        do {
            uint8_t len = 0; 
            UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, len));
            if (len > 0) {
                UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->session_id, (int32_t)len));
            }
        } while(0);

        // Unpack cipher suites.
        do {
            uint16_t len = 0; 
            UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, len));
            for (uint16_t i = 0; i < len; i += 2) {
                cipher_suite_type cipher_suite = TLS_CIPHER_SUITE_UNKNOWN; 
                UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, cipher_suite));
                raw->cipher_suites.push_back(cipher_suite);
            }
        } while(0);

        // Unpack compression methods.
        do {
            uint8_t len = 0;
            UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, len));
            for (uint8_t i = 0; i < len; i++) {
                compression_method_type compression_method = 0;
                UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, compression_method));
                raw->compression_methods.push_back(compression_method);
            }
        } while(0);

        // Unpack extensions length.
        uint16_t extensions_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, extensions_len));
        if (end < p + extensions_len) {
            return -1;
        }

        const uint8_t *extensions_end = p + extensions_len;
        while (p < extensions_end) {
            extension_type extension_type = -1;
            UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, extension_type));
            uint16_t extension_len = 0; 
            UNPACK_AND_RETURN_ERR( unpack_uint16(p, end, extension_len));
            switch (extension_type) {
            case TLS_EXTENSION_SERVER_NAME:
                for (const uint8_t *end = p + extension_len; p < end;) {
                    uint16_t len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, len));
                    uint8_t name_type = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, name_type));
                    uint16_t name_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, name_len));
                    if (end < p + name_len) {
                        return -1;
                    }
                    std::string name;
                    UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, name, name_len));
                    if (name_type == 0) {
                        raw->server_name = std::move(name);
                    }
                }
                break;
            case TLS_EXTENSION_STATUS_REQUEST:
                {
                    uint8_t status_type = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, status_type));
                    uint16_t ignored_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, ignored_len));
                    if (ignored_len > 0) {
                        std::string ignored;
                        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, ignored, (int32_t)ignored_len));
                    }
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, ignored_len));
                    if (ignored_len > 0) {
                        std::string ignored;
                        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, ignored, (int32_t)ignored_len));
                    }
                    if (status_type == 1) {
                        raw->is_support_ocsp_stapling = true;
                    }
                }
                break;
            case TLS_EXTENSION_SUPPORTED_GROUPS:
                {
                    uint16_t groups_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, groups_len));
                    if (extension_len != groups_len + 2) {
                        return -1;
                    }
                    for (uint16_t i = groups_len; i > 0; i -= 2) {
                        ssl::curve_group_type group_type = ssl::TLS_CURVE_UNKNOWN;
                        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, group_type));
                        raw->supported_groups.push_back(group_type);
                    }
                }
                break;
            case TLS_EXTENSION_SUPPORTED_POINTS:
                {
                    uint8_t points_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, points_len));
                    if (extension_len != points_len + 1) {
                        return -1;
                    }
                    for (uint8_t i = 0; i < points_len; i++) {
                        point_format_type point_type = TLS_POINT_FORMAT_UNCOMPRESSED;
                        UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, point_type));
                        raw->supported_points.push_back(point_type);
                    }
                }
                break;
            case TLS_EXTENSION_SESSION_TICKET:
                if (extension_len > 0) {
                    raw->is_support_session_ticket = true;
                    UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->session_ticket, (int32_t)extension_len));
                }
                break;
            case TLS_EXTENSION_SIGNATURE_ALGORITHMS:
                {
                    uint16_t schemes_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, schemes_len));
                    if (extension_len != schemes_len + 2) {
                        return -1;
                    }
                    for (uint16_t i = 0; i < schemes_len; i += 2) {
                        ssl::signature_scheme scheme = ssl::TLS_SIGN_SCHE_UNKNOWN;
                        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, scheme));
                        raw->supported_signature_schemes.push_back(scheme);
                    }
                }
                break;
            case TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT:
                {
                    uint16_t certs_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, certs_len));
                    if (extension_len != certs_len + 2) {
                        return -1;
                    }
                    for (uint16_t i = 0; i < certs_len; i += 2) {
                        uint16_t cert_type = 0;
                        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, cert_type));
                        raw->supported_signature_scheme_certs.push_back(cert_type);
                    }
                }
                break;
            case TLS_EXTENSION_RENEGOTIATION_INFO:
                {
                    uint8_t info_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, info_len));
                    if (extension_len != info_len + 1) {
                        return -1;
                    }
                    if (info_len > 0) {
                        raw->is_support_renegotiation_info = true;
                        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->renegotiation_info, (int32_t)info_len));
                    }
                }
                break;
            case TLS_EXTENSION_ALPN:
                {
                    uint16_t alpns_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, alpns_len));
                    if (extension_len != alpns_len + 2) {
                        return -1;
                    }
                    while(alpns_len > 0) {
                        uint8_t alpn_len = 0;
                        UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, alpn_len));
                        if (alpn_len == 0 || alpns_len < (uint16_t)alpn_len - 1) {
                            return -1;
                        }
                        std::string alpn;
                        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, alpn, (int32_t)alpn_len));
                        raw->alpns.push_back(std::move(alpn));
                        alpns_len -= uint16_t(1 + alpn_len);
                    }
                }
                break;
            case TLS_EXTENSION_SCT:
                raw->is_support_scts = true;
                break;
            case TLS_EXTENSION_SUPPORTED_VERSIONS:
                {
                    uint8_t versions_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, versions_len));
                    if (extension_len != uint16_t(versions_len + 1)) {
                        return -1;
                    }
                    for (uint8_t i = 0; i < versions_len; i += 2) {
                        version_type version = TLS_VERSION_UNKNOWN;
                        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, version));
                        raw->supported_versions.push_back(version);
                    }
                }
                break;
            case TLS_EXTENSION_COOKIE:
                {
                    uint16_t cookie_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, cookie_len));
                    if (extension_len != cookie_len + 2) {
                        return -1;
                    }
                    UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->cookie, (int32_t)cookie_len));
                }
                break;
            case TLS_EXTENSION_KEY_SHARE:
                {
                    uint16_t key_shares_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, key_shares_len));
                    if (extension_len != uint16_t(key_shares_len + 2)) {
                        return -1;
                    }
                    while(key_shares_len > 0) {
                        key_share key_share;
                        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, key_share.group));
                        uint16_t key_share_len = 0;
                        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, key_share_len));
                        if (key_shares_len < 2 + 2 + key_share_len) {
                            return -1;
                        }
                        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, key_share.data, (int32_t)key_share_len));
                        raw->key_shares.push_back(std::move(key_share));
                        key_shares_len -= (2 + 2 + key_share_len);
                    }
                }  
                break;
            case TLS_EXTENSION_EARLY_DATA:
                raw->is_support_early_data = true;
                break;
            case TLS_EXTENSION_PSK_MODES:
                {
                    uint8_t psk_modes_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, psk_modes_len));
                    if (extension_len != uint16_t(psk_modes_len + 2)) {
                        return -1;
                    }
                    for (uint8_t i = 0; i < psk_modes_len; i++) {
                        uint8_t psk_mode = 0;
                        UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, psk_mode));
                        raw->psk_modes.push_back(psk_mode);
                    }
                }
                break;
            case TLS_EXTENSION_PRE_SHARED_KEY:
                {
                    uint16_t psk_identities_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, psk_identities_len));
                    while (psk_identities_len > 0) {
                        uint16_t psk_identity_len = 0;
                        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, psk_identity_len));
                        psk_identity psk_identity;
                        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, psk_identity.identity, (int32_t)psk_identity_len));
                        UNPACK_AND_RETURN_ERR(unpack_uint32(p, end, psk_identity.obfuscated_ticket_age));
                        psk_identities_len -= (2 + psk_identity_len + 4);
                    }
                    uint16_t psk_binders_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, psk_binders_len));
                    while (psk_binders_len > 0) {
                        uint8_t psk_biner_len = 0;
                        UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, psk_biner_len));
                        std::string psk_binder;
                        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, psk_binder, (int32_t)psk_biner_len));
                        raw->psk_binders.push_back(std::move(psk_binder));
                        psk_binders_len -= uint16_t(1 + psk_biner_len);
                    }
                }
                break;
            default:
                {
                    extension additional_extension;
                    additional_extension.type = extension_type;
                    UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, additional_extension.data, (int32_t)extension_len));
                    raw->additional_extensions.push_back(std::move(additional_extension));
                }
                break;
            }
        }

        return int32_t(p - buf);
    }

    server_hello_message* new_server_hello() {
        auto msg = object_create<server_hello_message>();
        if (msg) {
            msg->legacy_version = TLS_VERSION_UNKNOWN;
            msg->is_support_ocsp_stapling = false;
            msg->is_support_session_ticket = false;
            msg->is_support_renegotiation_info = false;
            msg->supported_version = TLS_VERSION_UNKNOWN;
            msg->has_selected_key_share = false;
            msg->selected_group = ssl::TLS_CURVE_UNKNOWN;
            msg->has_selected_psk_identity = false;
        }
        return msg;
    }

    int32_t pack_server_hello(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const server_hello_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_SERVER_HELLO));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Pack server tls version with 2 bytes.
        PACK_AND_RETURN_ERR(pack_uint16(p, end, raw->legacy_version));

        // Pack random with 32 bytes.
        PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->random, 32));

        // Pack session id.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, (uint8_t)raw->session_id.size()));
        if (!raw->session_id.empty()) {
            PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->session_id));
        }

        // Pack cipher suite.
        PACK_AND_RETURN_ERR(pack_uint16(p, end, raw->cipher_suite));

        // Pack compression method.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, raw->compression_method));
        
        // Skip to pack extensions length with 2 bytes.
        uint8_t *extension_len = p; p += 2;

        if (raw->is_support_ocsp_stapling) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_STATUS_REQUEST));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 0));
        }

        if (raw->is_support_session_ticket) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SESSION_TICKET));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 0));
        }

        if (raw->is_support_renegotiation_info) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_RENEGOTIATION_INFO));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(2 + raw->renegotiation_info.size())));
            PACK_AND_RETURN_ERR(pack_uint8(p, end, (uint8_t)raw->renegotiation_info.size()));
            PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->renegotiation_info));
        }

        if (!raw->alpn.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_ALPN));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(2 + 1 + raw->alpn.size())));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(1 + raw->alpn.size())));
            PACK_AND_RETURN_ERR(pack_uint8(p, end, (uint8_t)raw->alpn.size()));
            PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->alpn));
        }

        if (!raw->scts.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SCT));
            uint8_t *len = p; p += 2 * 2;
            for (auto &sct : raw->scts) {
                PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)sct.size()));
                PACK_AND_RETURN_ERR(pack_bytes(p, end, sct));
            }
            pack_uint16(len, p, uint16_t(p - len - 2));
            pack_uint16(len + 2, p, uint16_t(p - len - 4));
        }

        if (raw->supported_version != 0) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SUPPORTED_VERSIONS));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 2));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, raw->supported_version));
        }

        if (raw->has_selected_key_share) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_KEY_SHARE));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(2 + 2 + raw->selected_key_share.data.size())));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, raw->selected_key_share.group));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)raw->selected_key_share.data.size()));
            PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->selected_key_share.data));
        }

        if (raw->selected_group != 0) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_KEY_SHARE));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 2));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, raw->selected_group));
        }

        if (raw->has_selected_psk_identity) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_PRE_SHARED_KEY));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 2));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, raw->selected_psk_identity));
        }

        if (!raw->cookie.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_COOKIE));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(2 + raw->cookie.size())));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)raw->cookie.size()));
            PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->cookie));
        }

        // Pack supported point formats extenion.
        if (!raw->supported_points.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SUPPORTED_POINTS));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(1 + raw->supported_points.size() * 2)));
            PACK_AND_RETURN_ERR(pack_uint8(p, end, (uint8_t)raw->supported_points.size()));
            for (auto point : raw->supported_points) {
                PACK_AND_RETURN_ERR(pack_uint8(p, end, point));
            }
        }

        // Pack extensions length.
        pack_uint16(extension_len, p, uint16_t(p - extension_len - 2));

        // Pack payload length.
        pack_uint24(payload_len, p, uint16_t(p - payload_len - 3));

        return int32_t(p - buf);
    }

    int32_t unpack_server_hello(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (server_hello_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_SERVER_HELLO) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        // Unpack client tls version.
        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, raw->legacy_version));

        // Unpack random with 32 bytes.
        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->random, 32));

        // Unpack session id.
        uint8_t session_id_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, session_id_len));
        if (session_id_len > 0) {
            UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->session_id, (int32_t)session_id_len));
        }

        // Unpack cipher suite.
        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, raw->cipher_suite));

        // Unpack compression method.
        UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, raw->compression_method));

        // Unpack extensions length.
        uint16_t extensions_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, extensions_len));
        if (end < p + extensions_len) {
            return -1;
        }

        const uint8_t *extensions_end = p + extensions_len;
        while (p < extensions_end) {
            uint16_t extension_type = -1;
            UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, extension_type));
            uint16_t extension_len = 0; 
            UNPACK_AND_RETURN_ERR( unpack_uint16(p, end, extension_len));
            switch (extension_type) {
            case TLS_EXTENSION_STATUS_REQUEST:
                raw->is_support_ocsp_stapling = true;
                break;
            case TLS_EXTENSION_SESSION_TICKET:
                raw->is_support_session_ticket = true;
                break;
            case TLS_EXTENSION_RENEGOTIATION_INFO:
                {
                    uint8_t info_len = 0;
                    UNPACK_AND_RETURN_ERR( unpack_uint8(p, end, info_len));
                    UNPACK_AND_RETURN_ERR( unpack_bytes(p, end, raw->renegotiation_info, (int32_t)info_len));
                    raw->is_support_renegotiation_info = true;
                }
                break;
            case TLS_EXTENSION_ALPN:
                {
                    uint16_t alpns_len = 0;
                    UNPACK_AND_RETURN_ERR( unpack_uint16(p, end, alpns_len));
                    uint8_t alpn_len = 0;
                    UNPACK_AND_RETURN_ERR( unpack_uint8(p, end, alpn_len));
                    UNPACK_AND_RETURN_ERR( unpack_bytes(p, end, raw->alpn, (int32_t)alpn_len));
                }
                break;
            case TLS_EXTENSION_SCT:
                {
                    uint16_t scts_len = 0;
                    UNPACK_AND_RETURN_ERR( unpack_uint16(p, end, scts_len));
                    while(scts_len > 0) {
                        uint16_t sct_len = 0;
                        UNPACK_AND_RETURN_ERR( unpack_uint16(p, end, sct_len));
                        if (scts_len < 2 + sct_len) { return -1; } 
                        scts_len -= (2 + sct_len);
                        std::string sct;
                        UNPACK_AND_RETURN_ERR( unpack_bytes(p, end, sct, (int32_t)sct_len));
                        raw->scts.push_back(std::move(sct));
                    }
                }
                break;
            case TLS_EXTENSION_SUPPORTED_VERSIONS:
                UNPACK_AND_RETURN_ERR( unpack_uint16(p, end, raw->supported_version));
                break;
            case TLS_EXTENSION_COOKIE:
                {
                    uint16_t cookie_len = 0;
                    UNPACK_AND_RETURN_ERR( unpack_uint16(p, end, cookie_len));
                    UNPACK_AND_RETURN_ERR( unpack_bytes(p, end, raw->cookie, (int32_t)cookie_len));
                }
                break;
            case TLS_EXTENSION_KEY_SHARE:
                if (extensions_len == 2) {
                    UNPACK_AND_RETURN_ERR( unpack_uint16(p, end, raw->selected_group));
                } else {
                    UNPACK_AND_RETURN_ERR( unpack_uint16(p, end, raw->selected_key_share.group));
                    uint16_t len = 0;
                    UNPACK_AND_RETURN_ERR( unpack_uint16(p, end, len));
                    UNPACK_AND_RETURN_ERR( unpack_bytes(p, end, raw->selected_key_share.data, (int32_t)len));
                    raw->has_selected_key_share = true;
                }
                break;
            case TLS_EXTENSION_PRE_SHARED_KEY:
                UNPACK_AND_RETURN_ERR( unpack_uint16(p, end, raw->selected_psk_identity));
                raw->has_selected_psk_identity = true;
                break;
            case TLS_EXTENSION_SUPPORTED_POINTS:
                {
                    uint8_t points_len = 0;
                    UNPACK_AND_RETURN_ERR( unpack_uint8(p, end, points_len));
                    for (uint8_t i = 0; i < points_len; i++) {
                        point_format_type point_type = 0;
                        UNPACK_AND_RETURN_ERR( unpack_uint8(p, end, point_type));
                        raw->supported_points.push_back(point_type);
                    }
                }
                break;
            default:
                p += extensions_len;
                break;
            }
        }

        return int32_t(p - buf); 
    }

    new_session_ticket_message* new_new_session_ticket() {
        auto msg = object_create<new_session_ticket_message>();
        if (msg) {
            msg->lifetime_hint = 0;
        }
        return msg;
    }

    int32_t pack_new_session_ticket(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const new_session_ticket_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_NEW_SESSION_TICKET));

        // Pack payload length.
        PACK_AND_RETURN_ERR(pack_uint24(p, end, uint32_t(4 + 2 + raw->ticket.size())));

        // Pack lifetime hint.
        PACK_AND_RETURN_ERR(pack_uint32(p, end, raw->lifetime_hint));

        // Pack ticket.
        PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)raw->ticket.size()));
        PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->ticket));

        return int32_t(p - buf);
    }

    int32_t unpack_new_session_ticket(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (new_session_ticket_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_NEW_SESSION_TICKET) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        // Unpack lifetime hint.
        UNPACK_AND_RETURN_ERR(unpack_uint32(p, end, raw->lifetime_hint));

        // Unpack ticket.
        uint16_t ticket_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, ticket_len));
        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->ticket, (uint32_t)ticket_len));

        return int32_t(p - buf);
    }

    new_session_ticket_tls13_message* new_new_session_ticket_tls13() {
        auto msg = object_create<new_session_ticket_tls13_message>();
        if (msg) {
            msg->lifetime = 0;
            msg->age_add = 0;
            msg->max_early_data_size = 0;
        }
        return msg;
    }

    int32_t pack_new_session_ticket_tls13(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const new_session_ticket_tls13_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_NEW_SESSION_TICKET));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Pack ticket lifetime.
        PACK_AND_RETURN_ERR(pack_uint32(p, end, raw->lifetime));

        // Pack ticket age add time.
        PACK_AND_RETURN_ERR(pack_uint32(p, end, raw->age_add));

        // Pack ticket nonce.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, (uint8_t)raw->nonce.size()));
        if (!raw->nonce.empty()) {
            PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->nonce));
        }

        // Pack ticket lable.
        PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)raw->label.size()));
        if (!raw->label.empty()) {
            PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->label));
        }

        // Pack extensions.
        if (raw->max_early_data_size == 0) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 0));
        } else {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 8));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_EARLY_DATA));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 2));
            PACK_AND_RETURN_ERR(pack_uint32(p, end, raw->max_early_data_size));
        }

        // Pack payload length.
        pack_uint24(payload_len, p, uint16_t(p - payload_len - 3));

        return int32_t(p - buf);
    }

    int32_t unpack_new_session_ticket_tls13(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (new_session_ticket_tls13_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_NEW_SESSION_TICKET) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        // Unpack ticket lifetime.
        UNPACK_AND_RETURN_ERR(unpack_uint32(p, end, raw->lifetime));

        // Unpack ticket age add time.
        UNPACK_AND_RETURN_ERR(unpack_uint32(p, end, raw->age_add));

        // Unpack ticket nonce.
        uint8_t nonce_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, nonce_len));
        if (nonce_len > 0) {
            UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->nonce, (int32_t)nonce_len));
        }

        // Unpack ticket lable.
        uint8_t lable_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, lable_len));
        if (lable_len > 0) {
            UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->label, (int32_t)lable_len));
        }

        // Unpack extensions.
        uint16_t extensions_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, extensions_len));
        if (extensions_len > 0) {
            uint16_t extension_type = 0;
            UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, extension_type));
            uint16_t extension_len = 0;
            UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, extension_len));
            UNPACK_AND_RETURN_ERR(unpack_uint32(p, end, raw->max_early_data_size));
        }

        return int32_t(p - buf);
    }

    end_early_data_message* new_end_early_data() {
        return object_create<end_early_data_message>();
    }

    int32_t pack_end_early_data(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_END_OF_EARLY_DATA));

        // Pack payload length.
        PACK_AND_RETURN_ERR(pack_uint24(p, end, 0));

        return int32_t(p - buf);  
    }

    int32_t unpack_end_early_data(const uint8_t *buf, int32_t size, void_ptr msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_END_OF_EARLY_DATA) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));
        if (payload_len != 0) {
            return -1;
        }

        return int32_t(p - buf);
    }

    encrypted_extensions_message* new_encrypted_extensions() {
        auto msg = object_create<encrypted_extensions_message>();
        if (msg) {
            msg->is_support_early_data = false;
        }
        return msg;
    }

    int32_t pack_encrypted_extensions(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const encrypted_extensions_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_ENCRYPTED_EXTENSIONS));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Skip to pack extensions length with 2 bytes.
        uint8_t *extension_len = p; p += 2;

        if (!raw->alpn.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_ALPN));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(2 + 1 + raw->alpn.size())));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(1 + raw->alpn.size())));
            PACK_AND_RETURN_ERR(pack_uint8(p, end, (uint8_t)raw->alpn.size()));
            PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->alpn)); 
        }

        if (raw->is_support_early_data) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_EARLY_DATA));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 0));
        }

        for (auto &ext : raw->additional_extensions) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, ext.type));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)ext.data.size()));
            PACK_AND_RETURN_ERR(pack_bytes(p, end, ext.data));
        }

        // Pack extensions length.
        pack_uint16(extension_len, p, uint16_t(p - extension_len - 2));

        // Pack payload length.
        pack_uint24(payload_len, p, uint16_t(p - payload_len - 3));

        return int32_t(p - buf);
    }

    int32_t unpack_encrypted_extensions(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (encrypted_extensions_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_ENCRYPTED_EXTENSIONS) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        // Unpack extensions length.
        uint16_t extensions_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, extensions_len));
        if (end < p + extensions_len) {
            return -1;
        }

        const uint8_t *extensions_end = p + extensions_len;
        while (p < extensions_end) {
            uint16_t extension_type = -1;
            UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, extension_type));
            uint16_t extension_len = 0; 
            UNPACK_AND_RETURN_ERR( unpack_uint16(p, end, extension_len));
            switch (extension_type) {
            case TLS_EXTENSION_ALPN:
                {
                    uint16_t alpns_len = 0;
                    UNPACK_AND_RETURN_ERR( unpack_uint16(p, end, alpns_len));
                    uint8_t alpn_len = 0;
                    UNPACK_AND_RETURN_ERR( unpack_uint8(p, end, alpn_len));
                    UNPACK_AND_RETURN_ERR( unpack_bytes(p, end, raw->alpn, (int32_t)alpn_len));
                }
                break;
            case TLS_EXTENSION_EARLY_DATA:
                raw->is_support_early_data = true;
                break;
            default:
                {
                    extension additional_extension;
                    additional_extension.type = extension_type;
                    UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, additional_extension.data, (int32_t)extension_len));
                    raw->additional_extensions.push_back(std::move(additional_extension));
                }
                break;
            }
        }

        return int32_t(p - buf); 
    }

    certificate_message* new_certificate() {
        return object_create<certificate_message>();
    }

    int32_t pack_certificate(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const certificate_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_CERTIFICATE));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Skip to pack certificates length with 3 bytes.
        uint8_t *certificates_len = p; p += 3;

        // Pack certificates.
        for (auto &cert : raw->certificates) {
            // Pack certificate.
            PACK_AND_RETURN_ERR(pack_uint24(p, end, (uint32_t)cert.size()));
            PACK_AND_RETURN_ERR(pack_bytes(p, end, cert));
        }

        // Pack certificates length.
        pack_uint24(certificates_len, p, uint32_t(p - certificates_len - 3));

        // Pack payload length.
        pack_uint24(payload_len, p, uint32_t(p - payload_len - 3));

        return int32_t(p - buf);
    }

    int32_t unpack_certificate(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (certificate_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CERTIFICATE) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        // Unpack certificates length.
        uint32_t certificates_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, certificates_len));
        if (end < p + certificates_len) {
            return -1;
        }

        // Unpack certificates.
        const uint8_t *certificates_end = p + certificates_len;
        while (p < certificates_end) {
            uint32_t certificate_len = 0;
            UNPACK_AND_RETURN_ERR(unpack_uint24(p, certificates_end, certificates_len));
            std::string certificate;
            UNPACK_AND_RETURN_ERR(unpack_bytes(p, certificates_end, certificate, (int32_t)certificate_len));
            raw->certificates.push_back(std::move(certificate));
        }

        return int32_t(p - buf);
    }

    certificate_tls13_message* new_certificate_tls13() {
        auto msg = object_create<certificate_tls13_message>();
        if (msg) {
            msg->is_support_ocsp_stapling = false;
            msg->is_support_scts = false;
        }
        return msg;
    }

    int32_t pack_certificate_tls13(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const certificate_tls13_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_CERTIFICATE));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Pack certificate request context length.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, 0));

        // Skip to pack certificates length with 3 bytes.
        uint8_t *certificates_len = p; p += 3;

        // Pack certificates.
        for (int32_t i = 0; i < (int32_t)raw->certificates.size(); i++) {
            if (i > 0) {
                break;
            }

            // Pack certificate.
            PACK_AND_RETURN_ERR(pack_uint24(p, end, (uint32_t)raw->certificates[i].size()));
            PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->certificates[i]));

            // Skip to pack extensions length.
            uint8_t *extensions_len = p; p += 2;

            // Pack status request extension.
            if (raw->is_support_ocsp_stapling) {
                PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_STATUS_REQUEST));
                PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(4 + raw->ocsp_staple.size())));
                PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_OCSP_STATUS));
                PACK_AND_RETURN_ERR(pack_uint24(p, end, (uint32_t)raw->ocsp_staple.size()));
                PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->ocsp_staple));
            }

            // Pack sct extension.
            if (raw->is_support_scts) {
                PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SCT));
                uint8_t *len = p; p += 2 * 2;
                for (int32_t ii = 0; ii < (int32_t)raw->scts.size(); ii++) {
                    PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)raw->scts[i].size()));
                    PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->scts[i]));
                }
                pack_uint16(len, p, uint16_t(p - len - 2));
                pack_uint16(len + 2, p, uint16_t(p - len - 4));
            }

            // Pack extensions length.
            pack_uint16(extensions_len, p, uint16_t(p - extensions_len - 2));
        }

        // Pack certificates length.
        pack_uint24(certificates_len, p, uint32_t(p - certificates_len - 3));

        // Pack payload length.
        pack_uint24(payload_len, p, uint32_t(p - payload_len - 3));

        return int32_t(p - buf);
    }

    int32_t unpack_certificate_tls13(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (certificate_tls13_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CERTIFICATE) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        // Unpack certificate request context length.
        uint8_t context_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, context_len));

        // Unpack certificates length.
        uint32_t certificates_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, certificates_len));
        if (end < p + certificates_len) {
            return -1;
        }

        // Unpack certificates.
        const uint8_t *certificates_end = p + certificates_len;
        while (p < certificates_end) {
            uint32_t certificate_len = 0;
            UNPACK_AND_RETURN_ERR(unpack_uint24(p, certificates_end, certificate_len));
            std::string certificate;
            UNPACK_AND_RETURN_ERR(unpack_bytes(p, certificates_end, certificate, (int32_t)certificate_len));

            uint16_t extensions_len = 0;
            UNPACK_AND_RETURN_ERR(unpack_uint16(p, certificates_end, extensions_len));

            const uint8_t *extensions_end = p + extensions_len;
            if (certificates_end < extensions_end) {
                return -1;
            }

            if (raw->certificates.size() > 0) {
                p += extensions_len;
                continue;
            }

            while (p < extensions_end) {
                uint16_t extension_type = -1;
                UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, extension_type));
                uint16_t extension_len = 0; 
                UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, extension_len));
                switch (extension_type) {
                case TLS_EXTENSION_STATUS_REQUEST:
                    {
                        uint8_t status = 0;
                        UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, status));
                        uint32_t ocsp_staple_len = 0;
                        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, ocsp_staple_len));
                        if (ocsp_staple_len > 0) {
                            UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->ocsp_staple, (int32_t)ocsp_staple_len)); 
                        }
                        raw->is_support_ocsp_stapling = true;
                    }
                    break;
                case TLS_EXTENSION_SCT:
                    {
                        uint16_t scts_len = 0;
                        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, scts_len));
                        while (scts_len > 0) {
                            uint16_t sct_len = 0;
                            UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, sct_len));
                            if (sct_len > 0) {
                                std::string sct;
                                UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, sct, (int32_t)sct_len));
                                raw->scts.push_back(std::move(sct));
                            }
                            scts_len -= (2 + sct_len);
                        }
                        raw->is_support_scts = true;
                    }
                    break;
                default:
                    p += extension_len;
                    break;
                }
            }

            raw->certificates.push_back(std::move(certificate));
        }

        return int32_t(p - buf);
    }

    server_key_exchange_message* new_server_key_exchange() {
        return object_create<server_key_exchange_message>();
    }

    int32_t pack_server_key_exchange(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const server_key_exchange_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_SERVER_KEY_EXCHANGE));

        // Pack payload length.
        PACK_AND_RETURN_ERR(pack_uint24(p, end, (uint32_t)raw->key.size()));

        // Pack key.
        PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->key));

        return int32_t(p - buf);
    }

    int32_t unpack_server_key_exchange(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (server_key_exchange_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_SERVER_KEY_EXCHANGE) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        // Unpack key.
        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->key, (int32_t)payload_len));

        return int32_t(p - buf);
    }

    certificate_request_message* new_certificate_request() {
        auto msg = object_create<certificate_request_message>();
        if (msg) {
            msg->has_signature_algorithms = false;
        }
        return msg;
    }

    int32_t pack_certificate_request(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const certificate_request_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_CERTIFICATE_REQUEST));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Pack certificate types.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, (uint8_t)raw->certificate_types.size()));
        for (auto cert_type : raw->certificate_types) {
            PACK_AND_RETURN_ERR(pack_uint8(p, end, cert_type));
        }

        // Pack signature algorithms.
        if (raw->has_signature_algorithms) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(raw->supported_signature_algorithms.size() * 2)));
            for (auto algo : raw->supported_signature_algorithms) {
                PACK_AND_RETURN_ERR(pack_uint16(p, end, algo));
            }
        }

        // Pack certificate authorities.
        uint8_t *certificate_authorities_len = p; p += 2;
        for (auto &auth : raw->certificate_authorities) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)auth.size()));
            PACK_AND_RETURN_ERR(pack_bytes(p, end, auth));
        }
        pack_uint16(certificate_authorities_len, end, uint16_t(p - certificate_authorities_len - 2));

        // Pack payload length.
        pack_uint24(payload_len, end, uint32_t(p - payload_len - 2));

        return int32_t(p - buf);
    }

    int32_t unpack_certificate_request(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (certificate_request_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CERTIFICATE_REQUEST) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        // Unpack certificate types.
        uint16_t certificate_types_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, certificate_types_len));
        for (int32_t i = 0; i < certificate_types_len; i++) {
            uint8_t certificate_type = 0;
            UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, certificate_type));
            raw->certificate_types.push_back(certificate_type);
        }

        if (raw->has_signature_algorithms) {
            uint16_t signature_algorithms_len = 0; 
            UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, signature_algorithms_len));
            for (uint16_t i = 0; i < signature_algorithms_len; i += 2) {
                uint16_t signature_algorithms = 0; 
                UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, signature_algorithms));
                raw->supported_signature_algorithms.push_back(signature_algorithms);
            }
        }

        // Unpack certificate authorities.
        uint16_t certificate_authorities_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, certificate_authorities_len));
        const uint8_t *certificate_authorities_end = p + certificate_authorities_len;
        while (p < certificate_authorities_end) {
            uint16_t cert_auth_len = 0; 
            UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, cert_auth_len));
            std::string cert_auth;
            UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, cert_auth, cert_auth_len));
            raw->certificate_authorities.push_back(std::move(cert_auth));
        }

        return int32_t(p - buf);
    }

    certificate_request_tls13_message* new_certificate_request_tls13() {
        auto msg = object_create<certificate_request_tls13_message>();
        if (msg) {
            msg->is_support_ocsp_stapling = false;
            msg->is_support_scts = false;
        }
        return msg;
    }

    int32_t pack_certificate_request_tls13(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const certificate_request_tls13_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_CERTIFICATE_REQUEST));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Pack certificate request context length.
        // SHALL be zero length unless used for post-handshake authentication.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, 0));

        // Skip to pack extensions length with 2 bytes.
        uint8_t *extension_len = p; p += 2;

        // Pack status request extension.
        if (raw->is_support_ocsp_stapling) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_STATUS_REQUEST));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 0));
        }

        // Pack sct extension.
        if (raw->is_support_scts) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SCT));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, 0));
        }

        // Pack signature algorithms extension.
        if (!raw->supported_signature_schemes.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SIGNATURE_ALGORITHMS));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(2 + raw->supported_signature_schemes.size() * 2)));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(raw->supported_signature_schemes.size() * 2)));
            for (auto scheme : raw->supported_signature_schemes) {
                PACK_AND_RETURN_ERR(pack_uint16(p, end, scheme));
            }
        }

        // Pack signature algorithms certs extension.
        if (!raw->supported_signature_algorithms_certs.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(2 + raw->supported_signature_algorithms_certs.size() * 2)));
            PACK_AND_RETURN_ERR(pack_uint16(p, end, uint16_t(raw->supported_signature_algorithms_certs.size() * 2)));
            for (auto algo : raw->supported_signature_algorithms_certs) {
                PACK_AND_RETURN_ERR(pack_uint16(p, end, algo));
            }
        }

        // Pack signature algorithms certs extension.
        if (!raw->certificate_authorities.empty()) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, TLS_EXTENSION_CERTIFICATE_AUTHORITIES));
            uint8_t *len = p; p += 2 * 2;
            for (auto &cert_auth : raw->certificate_authorities) {
                PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)cert_auth.size()));
                PACK_AND_RETURN_ERR(pack_bytes(p, end, cert_auth));
            }
            pack_uint16(len, p, uint16_t(p - len - 2));
            pack_uint16(len + 2, p, uint16_t(p - len - 4));
        }

        // Pack extensions length.
        pack_uint16(extension_len, p, uint16_t(p - extension_len - 2));

        // Pack payload length.
        pack_uint24(payload_len, p, uint16_t(p - payload_len - 3));

        return int32_t(p - buf);
    }

    int32_t unpack_certificate_request_tls13(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (certificate_request_tls13_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CERTIFICATE_REQUEST) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        // Unpack certificate request context length.
        // SHALL be zero length unless used for post-handshake authentication.
        uint8_t context_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, context_len));

        // Unpack extensions length.
        uint16_t extensions_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, extensions_len));
        if (end < p + extensions_len) {
            return -1;
        }

        const uint8_t *extensions_end = p + extensions_len;
        while (p < extensions_end) {
            uint16_t extension_type = -1;
            UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, extension_type));
            uint16_t extension_len = 0; 
            UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, extension_len));
            switch (extension_type) {
            case TLS_EXTENSION_STATUS_REQUEST:
                raw->is_support_ocsp_stapling = true;
                break;
            case TLS_EXTENSION_SCT:
                raw->is_support_scts = true;
                break;
            case TLS_EXTENSION_SIGNATURE_ALGORITHMS:
                {
                    uint16_t schemes_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, schemes_len));
                    for (uint16_t i = 0; i < schemes_len; i += 2) {
                        ssl::signature_scheme scheme = ssl::TLS_SIGN_SCHE_UNKNOWN;
                        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, scheme));
                        raw->supported_signature_schemes.push_back(scheme);
                    }
                }
                break;
            case TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT:
                {
                    uint16_t algo_certs_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, algo_certs_len));
                    for (uint16_t i = 0; i < algo_certs_len; i += 2) {
                        ssl::signature_scheme algo_cert = ssl::TLS_SIGN_SCHE_UNKNOWN;
                        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, algo_cert));
                        raw->supported_signature_algorithms_certs.push_back(algo_cert);
                    }
                }
                break;
            case TLS_EXTENSION_CERTIFICATE_AUTHORITIES:
                {
                    uint16_t cert_auths_len = 0;
                    UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, cert_auths_len));
                    while (cert_auths_len > 0) {
                        uint8_t cert_auth_len = 0;
                        UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, cert_auth_len));
                        std::string cert_auth;
                        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, cert_auth, (int32_t)cert_auth_len));
                        raw->certificate_authorities.push_back(std::move(cert_auth));
                        cert_auths_len -= uint16_t(2 + cert_auth_len);
                    }
                }
                break;
            default:
                p += extensions_len;
                break;
            }
        }

        return int32_t(p - buf);
    }

    server_hello_done_message* new_server_hello_done() {
        return object_create<server_hello_done_message>();
    }

    int32_t pack_server_hello_done(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_SERVER_HELLO_DONE));

        // Pack payload length.
        PACK_AND_RETURN_ERR(pack_uint24(p, end, 0));

        return int32_t(p - buf);
    }

    int32_t unpack_server_hello_done(const uint8_t *buf, int32_t size, void_ptr msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_SERVER_HELLO_DONE) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        return int32_t(p - buf);
    }

    certificate_verify_message* new_certificate_verify() {
        auto msg = object_create<certificate_verify_message>();
        if (msg) {
            msg->has_signature_scheme = true;
        }
        return msg;
    }

    int32_t pack_certificate_verify(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const certificate_verify_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_CERTIFICATE_VERIFY));

        // Pack payload length.
        if (raw->has_signature_scheme) {
            PACK_AND_RETURN_ERR(pack_uint24(p, end, uint32_t(2 + 2 + raw->signature.size())));
        } else {
            PACK_AND_RETURN_ERR(pack_uint24(p, end, uint32_t(2 + raw->signature.size())));
        }
        
        if (raw->has_signature_scheme) {
            PACK_AND_RETURN_ERR(pack_uint16(p, end, raw->signature_scheme));
        }

        // Pack signature data.
        PACK_AND_RETURN_ERR(pack_uint16(p, end, (uint16_t)raw->signature.size()));
        PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->signature));

        return int32_t(p - buf);
    }

    int32_t unpack_certificate_verify(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (certificate_verify_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CERTIFICATE_VERIFY) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        if (raw->has_signature_scheme) {
            UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, raw->signature_scheme));
        }

        uint16_t signature_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint16(p, end, signature_len));
        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->signature, signature_len));

        return int32_t(p - buf);
    }

    client_key_exchange_message* new_client_key_exchange() {
        return object_create<client_key_exchange_message>();
    }

    int32_t pack_client_key_exchange(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const client_key_exchange_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_CLIENT_KEY_EXCHANGE));

        // Pack payload length.
        PACK_AND_RETURN_ERR(pack_uint24(p, end, (uint32_t)raw->ciphertext.size()));

        // Pack ciphertext.
        PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->ciphertext));

        return int32_t(p - buf);
    }

    int32_t unpack_client_key_exchange(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (client_key_exchange_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CLIENT_KEY_EXCHANGE) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        // Unpack ciphertext.
        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->ciphertext, (int32_t)payload_len));

        return int32_t(p - buf);
    }

    finished_message* new_finished() {
        return object_create<finished_message>();
    }

    int32_t pack_finished(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const finished_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_FINISHED));

        // Pack payload length.
        PACK_AND_RETURN_ERR(pack_uint24(p, end, (uint32_t)raw->verify_data.size()));

        // Pack verify data.
        PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->verify_data));

        return int32_t(p - buf);
    }

    int32_t unpack_finished(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (finished_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_FINISHED) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        // Unpack verify data.
        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->verify_data, (int32_t)payload_len));

        return int32_t(p - buf);
    }

    certificate_status_message* new_certificate_status() {
        return object_create<certificate_status_message>();
    }

    int32_t pack_certificate_status(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const certificate_status_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_CERTIFICATE_STATUS));

        // Pack payload length.
        PACK_AND_RETURN_ERR(pack_uint24(p, end, uint32_t(1 + 3 + raw->response.size())));

        // Pack status.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_OCSP_STATUS));
        PACK_AND_RETURN_ERR(pack_uint24(p, end, (uint32_t)raw->response.size()));
        PACK_AND_RETURN_ERR(pack_bytes(p, end, raw->response));

        return int32_t(p - buf);
    }

    int32_t unpack_certificate_status(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (certificate_status_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CERTIFICATE_STATUS) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));

        // Unpack status.
        certicate_status_type status_type;
        UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, status_type));
        uint32_t status_len = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, status_len));
        UNPACK_AND_RETURN_ERR(unpack_bytes(p, end, raw->response, (int32_t)status_len));

        return int32_t(p - buf);
    }

    key_update_message* new_key_update() {
        auto msg = object_create<key_update_message>();
        if (msg) {
            msg->update_requested = false;
        }
        return msg;
    }

    int32_t pack_key_update(c_void_ptr msg, uint8_t *buf, int32_t max_size) {
        auto raw = (const key_update_message*)msg;

        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(pack_uint8(p, end, TLS_MSG_KEY_UPDATE));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        if (raw->update_requested) {
            PACK_AND_RETURN_ERR(pack_uint8(p, end, 1));
        } else {
            PACK_AND_RETURN_ERR(pack_uint8(p, end, 0));
        }

        // Pack payload length.
        PACK_AND_RETURN_ERR(pack_uint24(payload_len, end, 0));

        return int32_t(p - buf);
    }

    int32_t unpack_key_update(const uint8_t *buf, int32_t size, void_ptr msg) {
        auto raw = (key_update_message*)msg;

        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_KEY_UPDATE) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(unpack_uint24(p, end, payload_len));
        if (payload_len != 1) {
            return -1;
        }

        uint8_t update_requested = 0;
        UNPACK_AND_RETURN_ERR(unpack_uint8(p, end, update_requested));
        raw->update_requested = (update_requested == 1);

        return int32_t(p - buf);
    }

    std::string pack_message_hash(const std::string &hash) {
        std::string out(4 + hash.size(), 0);
        uint8_t *p = (uint8_t*)out.data();
        uint8_t *end = p + out.size();
        p = pack_uint8(p, end, TLS_MSG_MESSAGE_HASH);
        p = pack_uint16(p, end, 0);
        p = pack_uint8(p, end, (int8_t)hash.size());
        p = pack_bytes(p, end, hash);
        return std::forward<std::string>(out);
    }

#undef PACK_AND_RETURN_ERR

#undef UNPACK_AND_RETURN_ERR

}
}
}
}