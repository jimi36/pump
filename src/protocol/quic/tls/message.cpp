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

#include "pump/utils.h"
#include "pump/memory.h"
#include "pump/protocol/quic/tls/message.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {
    
    handshake_message* new_handshake_message(message_type type) {
        handshake_message *msg = object_create<handshake_message>();
        if (msg == nullptr) {
            return nullptr;
        }

        msg->type = type;
        msg->msg = nullptr;

        switch (type) {
        case TLS_MSG_HELLO_REQUEST:
            msg->msg = (void*)object_create<hello_request_message>();
            break;
        case TLS_MSG_CLIENT_HELLO:
            msg->msg = (void*)object_create<client_hello_message>();
            break;
        case TLS_MSG_SERVER_HELLO:
            msg->msg = (void*)object_create<server_hello_message>();
            break;
        case TLS_MSG_NEW_SESSION_TICKET:
            msg->msg = (void*)object_create<new_session_ticket_tls13_message>();
            break;
        case TLS_MSG_END_OF_EARLY_DATA:
            msg->msg = (void*)object_create<end_early_data_message>();
            break;
        case TLS_MSG_ENCRYPTED_EXTENSIONS:
            msg->msg = (void*)object_create<encrypted_extensions_message>();
            break;
        case TLS_MSG_CERTIFICATE:
            msg->msg = (void*)object_create<certificate_tls13_message>();
            break;
        case TLS_MSG_SERVER_KEY_EXCHANGE:
            msg->msg = (void*)object_create<server_key_exchange_message>();
            break;
        case TLS_MSG_CERTIFICATE_REQUEST:
            msg->msg = (void*)object_create<certificate_request_tls13_message>();
            break;
        case TLS_MSG_SERVER_HELLO_DONE:
            msg->msg = (void*)object_create<server_hello_done_message>();
            break;
        case TLS_MSG_CERTIFICATE_VERIFY:
            msg->msg = (void*)object_create<certificate_verify_message>();
            break;
        case TLS_MSG_CLIENT_KEY_EXCHANGE:
            msg->msg = (void*)object_create<client_key_exchange_message>();
            break;
        case TLS_MSG_FINISHED:
            msg->msg = (void*)object_create<finished_message>();
            break;
        case TLS_MSG_CERTIFICATE_STATUS:
            msg->msg = (void*)object_create<certificate_status_message>();
            break;
        case TLS_MSG_KEY_UPDATE:
            msg->msg = (void*)object_create<key_update_message>();
            break;
        default:
            break;
        }

        if (msg->msg == nullptr) {
            object_delete(msg);
            return nullptr;
        }

        return msg;
    }

    void delete_handshake_message(handshake_message *msg) {
        if (msg == nullptr) {
            return;
        }

        if (msg->msg != nullptr) {
            switch (msg->type) {
            case TLS_MSG_HELLO_REQUEST:
                object_delete((hello_request_message*)msg->msg);
                break;
            case TLS_MSG_CLIENT_HELLO:
                object_delete((client_hello_message*)msg->msg);
                break;
            case TLS_MSG_SERVER_HELLO:
                object_delete((server_hello_message*)msg->msg);
                break;
            case TLS_MSG_NEW_SESSION_TICKET:
                object_delete((new_session_ticket_tls13_message*)msg->msg);
                break;
            case TLS_MSG_END_OF_EARLY_DATA:
                object_delete((end_early_data_message*)msg->msg);
                break;
            case TLS_MSG_ENCRYPTED_EXTENSIONS:
                object_delete((encrypted_extensions_message*)msg->msg);
                break;
            case TLS_MSG_CERTIFICATE:
                object_delete((certificate_tls13_message*)msg->msg);
                break;
            case TLS_MSG_SERVER_KEY_EXCHANGE:
                object_delete((server_key_exchange_message*)msg->msg);
                break;
            case TLS_MSG_CERTIFICATE_REQUEST:
                object_delete((certificate_request_tls13_message*)msg->msg);
                break;
            case TLS_MSG_SERVER_HELLO_DONE:
                object_delete((server_hello_done_message*)msg->msg);
                break;
            case TLS_MSG_CERTIFICATE_VERIFY:
                object_delete((certificate_verify_message*)msg->msg);
                break;
            case TLS_MSG_CLIENT_KEY_EXCHANGE:
                object_delete((client_key_exchange_message*)msg->msg);
                break;
            case TLS_MSG_FINISHED:
                object_delete((finished_message*)msg->msg);
                break;
            case TLS_MSG_CERTIFICATE_STATUS:
                object_delete((certificate_status_message*)msg->msg);
                break;
            case TLS_MSG_KEY_UPDATE:
                object_delete((key_update_message*)msg->msg);
                break;
            default:
                break;
            }
        }

        object_delete(msg);
    }

    const std::string& pack_handshake_message(handshake_message *msg) {
        if (!msg->packed_data.empty()) {
            return msg->packed_data;
        }

        int32_t packed_data_size = 2048;

#define PACK_MESSAGE(pack, msg_type) \
    msg->packed_data.resize(packed_data_size); \
    packed_data_size = pack((const msg_type*)msg->msg, (uint8_t*)msg->packed_data.data(), packed_data_size); \
    break;
    
        switch (msg->type) {
        case TLS_MSG_HELLO_REQUEST:
            PACK_MESSAGE(pack_hello_request, hello_request_message)
        case TLS_MSG_CLIENT_HELLO:
            PACK_MESSAGE(pack_client_hello, client_hello_message)
        case TLS_MSG_SERVER_HELLO:
            PACK_MESSAGE(pack_server_hello, server_hello_message)
        case TLS_MSG_NEW_SESSION_TICKET:
            PACK_MESSAGE(pack_new_session_ticket_tls13, new_session_ticket_tls13_message)
        case TLS_MSG_END_OF_EARLY_DATA:
            PACK_MESSAGE(pack_end_early_data, end_early_data_message)
        case TLS_MSG_ENCRYPTED_EXTENSIONS:
            PACK_MESSAGE(pack_encrypted_extensions, encrypted_extensions_message)
        case TLS_MSG_CERTIFICATE:
            PACK_MESSAGE(pack_certificate_tls13, certificate_tls13_message)
        case TLS_MSG_SERVER_KEY_EXCHANGE:
            PACK_MESSAGE(pack_server_key_exchange, server_key_exchange_message)
        case TLS_MSG_CERTIFICATE_REQUEST:
            PACK_MESSAGE(pack_certificate_request_tls13, certificate_request_tls13_message)
        case TLS_MSG_SERVER_HELLO_DONE:
            PACK_MESSAGE(pack_server_hello_done, server_hello_done_message)
        case TLS_MSG_CERTIFICATE_VERIFY:
            PACK_MESSAGE(pack_certificate_verify, certificate_verify_message)
        case TLS_MSG_CLIENT_KEY_EXCHANGE:
            PACK_MESSAGE(pack_client_key_exchange, client_key_exchange_message)
        case TLS_MSG_FINISHED:
            PACK_MESSAGE(pack_finished, finished_message)
        case TLS_MSG_CERTIFICATE_STATUS:
            PACK_MESSAGE(pack_certificate_status, certificate_status_message)
        case TLS_MSG_KEY_UPDATE:
            PACK_MESSAGE(pack_key_update, key_update_message)
        default:
            return msg->packed_data;
        }

#undef PACK_MESSAGE

        if (packed_data_size < 0) {
            packed_data_size = 0;
        }
        msg->packed_data.resize(packed_data_size);

        return msg->packed_data;
    }

    int32_t unpack_handshake_message(
        const uint8_t *buf, 
        int32_t size, 
        handshake_message *msg) {
        if (msg == nullptr || msg->msg == nullptr) {
            return -1; 
        }

        int32_t unpack_size = 0;
        switch (buf[0]) {
        case TLS_MSG_HELLO_REQUEST:
            unpack_size = unpack_hello_request(buf, size, (hello_request_message*)msg->msg);
            break;
        case TLS_MSG_CLIENT_HELLO:
            unpack_size = unpack_client_hello(buf, size, (client_hello_message*)msg->msg);
            break;
        case TLS_MSG_SERVER_HELLO:
            unpack_size = unpack_server_hello(buf, size, (server_hello_message*)msg->msg);
            break;
        case TLS_MSG_NEW_SESSION_TICKET:
            unpack_size = unpack_new_session_ticket_tls13(buf, size, (new_session_ticket_tls13_message*)msg->msg);
            break;
        case TLS_MSG_END_OF_EARLY_DATA:
            unpack_size = unpack_end_early_data(buf, size, (end_early_data_message*)msg->msg);
            break;
        case TLS_MSG_ENCRYPTED_EXTENSIONS:
            unpack_size = unpack_encrypted_extensions(buf, size, (encrypted_extensions_message*)msg->msg);
            break;
        case TLS_MSG_CERTIFICATE:
            unpack_size = unpack_certificate_tls13(buf, size, (certificate_tls13_message*)msg->msg);
            break;
        case TLS_MSG_SERVER_KEY_EXCHANGE:
            unpack_size = unpack_server_key_exchange(buf, size, (server_key_exchange_message*)msg->msg);
            break;
        case TLS_MSG_CERTIFICATE_REQUEST:
            unpack_size = unpack_certificate_request_tls13(buf, size, (certificate_request_tls13_message*)msg->msg);
            break;
        case TLS_MSG_SERVER_HELLO_DONE:
            unpack_size = unpack_server_hello_done(buf, size, (server_hello_done_message*)msg->msg);
            break;
        case TLS_MSG_CERTIFICATE_VERIFY:
            unpack_size = unpack_certificate_verify(buf, size, (certificate_verify_message*)msg->msg);
            break;
        case TLS_MSG_CLIENT_KEY_EXCHANGE:
            unpack_size = unpack_client_key_exchange(buf, size, (client_key_exchange_message*)msg->msg);
            break;
        case TLS_MSG_FINISHED:
            unpack_size = unpack_finished(buf, size, (finished_message*)msg->msg);
            break;
        case TLS_MSG_CERTIFICATE_STATUS:
            unpack_size = unpack_certificate_status(buf, size, (certificate_status_message*)msg->msg);
            break;
        case TLS_MSG_KEY_UPDATE:
            unpack_size = unpack_key_update(buf, size, (key_update_message*)msg->msg);
            break;
        default:
            return -1;
        }

        if (unpack_size > 0) {
            msg->packed_data.assign((char*)buf, unpack_size);
        }

        return unpack_size;
    }

    PUMP_INLINE uint8_t* __pack_bytes(uint8_t *des, uint8_t *end, const uint8_t *src, int32_t size) {
        if (end < des + size) {
            return nullptr;
        }
        memcpy(des, src, size);
        return des + size;
    }

    PUMP_INLINE const uint8_t* __unpack_bytes(const uint8_t *src, const uint8_t *end, uint8_t *des, int32_t size) {
        if (end < src + size) {
            return nullptr;
        }
        memcpy(des, src, size);
        return src + size;
    }

    PUMP_INLINE uint8_t* __pack_bytes(uint8_t *des, uint8_t *end, const std::string &src) {
        if (end < des + (int32_t)src.size()) {
            return nullptr;
        }
        memcpy(des, src.c_str(), (int32_t)src.size());
        return des + (int32_t)src.size();
    }

    PUMP_INLINE const uint8_t* __unpack_bytes(const uint8_t *src, const uint8_t *end, std::string &des, int32_t size) {
        if (end < src + size) {
            return nullptr;
        }
        des.assign((const char*)src, size);
        return src + size;
    }

    PUMP_INLINE uint8_t* __pack_uint8(uint8_t *p, uint8_t *end, uint8_t val) {
        if (end < p + 1) {
            return nullptr;
        }
        *(p++) = val;
        return p;
    }

    PUMP_INLINE const uint8_t* __unpack_uint8(const uint8_t *p, const uint8_t *end, uint8_t &val) {
        if (end < p + 1) {
            return nullptr;
        }
        val = *(p++);
        return p;
    }

    PUMP_INLINE uint8_t* __pack_uint16(uint8_t *p, uint8_t *end, uint16_t val) {
        if (end < p + 2) {
            return nullptr;
        }
        *((uint16_t*)p) = pump::change_endian(val);
        return p + 2;
    }

    PUMP_INLINE const uint8_t* __unpack_uint16(const uint8_t *p, const uint8_t *end, uint16_t &val) {
        if (end < p + 2) {
            return nullptr;
        }
        val = pump::change_endian(*((uint16_t*)p));
        return p + 2;
    }

    PUMP_INLINE uint8_t* __pack_uint24(uint8_t *p, uint8_t *end, uint32_t val) {
        if (end < p + 3) {
            return nullptr;
        }
        *(p + 0) = int8_t(val >> 16);
        *(p + 1) = int8_t(val >> 8);
        *(p + 2) = int8_t(val);
        return p + 3;
    }

    PUMP_INLINE const uint8_t* __unpack_uint24(const uint8_t *p, const uint8_t *end, uint32_t &val) {
        if (end < p + 3) {
            return nullptr;
        }
        val = (uint32_t(*(p + 0)) << 16) |
              (uint32_t(*(p + 1)) << 8) |
              (uint32_t(*(p + 2))) ;
        return p + 3;
    }

    PUMP_INLINE uint8_t* __pack_uint32(uint8_t *p, uint8_t *end, uint32_t val) {
        if (end <  p + 4) {
            return nullptr;
        }
        *((uint32_t*)p) = pump::change_endian(val);
        return p + 4;
    }

    PUMP_INLINE const uint8_t* __unpack_uint32(const uint8_t *p, const uint8_t *end, uint32_t &val) {
        if (end < p + 4) {
            return nullptr;
        }
        val = pump::change_endian(*((uint32_t*)p));
        return p + 4;
    }

#define PACK_AND_RETURN_ERR(pack) \
    p = pack; \
    if (!p) { return -1; } void(0)

#define UNPACK_AND_RETURN_ERR(unpack) \
    p = unpack; \
    if (!p) { return -1; } void(0)

    int32_t pack_hello_request(const hello_request_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_HELLO_REQUEST));

        // Pack payload length.
        PACK_AND_RETURN_ERR(__pack_uint24(p, end, 0));

        return int32_t(p - buf);
    }

    int32_t unpack_hello_request(const uint8_t *buf, int32_t size, hello_request_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_HELLO_REQUEST) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        return int32_t(p - buf);
    }

    int32_t pack_client_hello(const client_hello_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_CLIENT_HELLO));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Pack client tls version with 2 bytes.
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->legacy_version));

        // Pack random with 32 bytes.
        PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->random, 32));

        // Pack session id.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->session_id.size()));
        if (!msg->session_id.empty()) {
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->session_id));
        }

        // Pack cipher suites.
        do {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(msg->cipher_suites.size() * 2)));
            for (int32_t i = 0; i < (int32_t)msg->cipher_suites.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->cipher_suites[i]));
            }
        } while(0);

        // Pack compression methods.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->compression_methods.size()));
        for (int32_t i = 0; i < (int32_t)msg->compression_methods.size(); i++) {
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, msg->compression_methods[i]));
        }
        
        // Skip to pack extensions length with 2 bytes.
        uint8_t *extension_len = p; p += 2;

        // Pack server name extenion.
        if (!msg->server_name.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SERVER_NAME));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + 1 + 2 + msg->server_name.size())));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(1 + 2 + msg->server_name.size())));
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, 0)); // name_type = host_name
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->server_name.size())); // server name length
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->server_name));
        }

        // Pack ocsp extenion.
        if (msg->is_support_ocsp_stapling) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_STATUS_REQUEST));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 5));
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, 1)); // status_type = ocsp
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 0)); // empty responder_id_list
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 0)); // empty request_extensions
        }

        // Pack supported curve groups extenion.
        if (!msg->supported_groups.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SUPPORTED_GROUPS));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + msg->supported_groups.size() * 2)));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(msg->supported_groups.size() * 2)));
            for (int32_t i = 0; i < (int32_t)msg->supported_groups.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->supported_groups[i]));
            }
        }

        // Pack supported point formats extenion.
        if (!msg->supported_points.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SUPPORTED_POINTS));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(1 + msg->supported_points.size())));
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->supported_points.size()));
            for (int32_t i = 0; i < (int32_t)msg->supported_points.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint8(p, end, msg->supported_points[i]));
            }
        }

        // Pack session ticket extenion.
        if (msg->is_support_session_ticket) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SESSION_TICKET));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->session_ticket.size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->session_ticket));
        }

        // Pack supported signature algorithms extenion.
        if (!msg->supported_signature_schemes.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SIGNATURE_ALGORITHMS));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + msg->supported_signature_schemes.size() * 2)));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(msg->supported_signature_schemes.size() * 2)));
            for (int32_t i = 0; i < (int32_t)msg->supported_signature_schemes.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->supported_signature_schemes[i]));
            }
        }

        // Pack supported signature algorithms certs extenion.
        if (!msg->supported_signature_scheme_certs.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + msg->supported_signature_scheme_certs.size() * 2)));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(msg->supported_signature_scheme_certs.size() * 2)));
            for (int32_t i = 0; i < (int32_t)msg->supported_signature_scheme_certs.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->supported_signature_scheme_certs[i]));
            }
        }

        // Pack renegotiation info extenion.
        if (msg->is_support_renegotiation_info) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_RENEGOTIATION_INFO));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(1 + msg->renegotiation_info.size())));
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->renegotiation_info.size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->renegotiation_info));
        }

        // Pack application layer protocol negotiation extenion.
        if (!msg->alpns.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_ALPN));
            uint8_t *len = p; p += 2 * 2;
            for (int32_t i = 0; i < (int32_t)msg->alpns.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->alpns[i].size()));
                PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->alpns[i]));
            }
            __pack_uint16(len, p, uint16_t(p - len - 2));
            __pack_uint16(len + 2, p, uint16_t(p - len - 4));
        }

        // Pack signed certificate timestamp extenion.
        if (msg->is_support_scts) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SCT));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 0)); // empty extension_data
        }

        // Pack supported versions extenion.
        if (!msg->supported_versions.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SUPPORTED_VERSIONS));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(1 + msg->supported_versions.size() * 2)));
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, uint8_t(msg->supported_versions.size() * 2)));
            for (int32_t i = 0; i < (int32_t)msg->supported_versions.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->supported_versions[i]));
            }
        }

        // Pack cookie extenion.
        if (!msg->cookie.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_COOKIE));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + msg->cookie.size())));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->cookie.size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->cookie));
        }

        // Pack key shares extenion.
        if (!msg->key_shares.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_KEY_SHARE));
            uint8_t *len = p; p += 2 * 2;
            for (int32_t i = 0; i <  (int32_t)msg->key_shares.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->key_shares[i].group));
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->key_shares[i].data.size()));
                PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->key_shares[i].data));
            }
            __pack_uint16(len, p, uint16_t(p - len - 2));
            __pack_uint16(len + 2, p, uint16_t(p - len - 4));
        }

        // Pack early data extenion.
        if (msg->is_support_early_data) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_EARLY_DATA));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 0)); // empty extension_data
        }

        // Pack psk modes extenion.
        if (!msg->psk_modes.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_PSK_MODES));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(1 + msg->psk_modes.size())));
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->psk_modes.size()));
            for (int32_t i = 0; i < (int32_t)msg->psk_modes.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint8(p, end, msg->psk_modes[i]));
            }
        }

        // Pack additional extensions.
        for (int32_t i = 0; i < (int32_t)msg->additional_extensions.size(); i++) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->additional_extensions[i].type));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->additional_extensions[i].data.size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->additional_extensions[i].data));
        }

        // Pack psk identities extenion.
        if (!msg->psk_identities.empty()) { // Must serizlize the extenion at last.
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_PRE_SHARED_KEY));
            uint8_t *len1 = p; p += 2;
            {
                uint8_t *len2 = p; p += 2;
                for (int32_t i = 0; i < (int32_t)msg->psk_identities.size(); i++) {
                    PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->psk_identities[i].identity.size()));
                    PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->psk_identities[i].identity));
                    PACK_AND_RETURN_ERR(__pack_uint32(p, end, msg->psk_identities[i].obfuscated_ticket_age));
                }
                __pack_uint16(len2, p, uint16_t(p - len2 - 2));
            }
            {
                uint8_t *len2 = p; p += 2;
                for (int32_t i = 0; i < (int32_t)msg->psk_binders.size(); i++) {
                    PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->psk_binders[i].size()));
                    PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->psk_binders[i]));
                }
                __pack_uint16(len2, p, uint16_t(p - len2 - 2));
            }
            __pack_uint16(len1, p, uint16_t(p - len1 - 2));
        }

        // Pack extensions length.
        __pack_uint16(extension_len, p, uint16_t(p - extension_len - 2));

        // Pack payload length.
        __pack_uint24(payload_len, p, uint16_t(p - payload_len - 3));

        return int32_t(p - buf);
    }

    int32_t unpack_client_hello(const uint8_t *buf, int32_t size, client_hello_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CLIENT_HELLO) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        // Unpack client tls version.
        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, msg->legacy_version));

        // Unpack random with 32 bytes.
        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->random, 32));

        // Unpack session id.
        do {
            uint8_t len = 0; 
            UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, len));
            if (len > 0) {
                UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->session_id, (int32_t)len));
            }
        } while(0);

        // Unpack cipher suites.
        do {
            uint16_t len = 0; 
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, len));
            for (uint16_t i = 0; i < len; i += 2) {
                cipher_suite_type cipher_suite = TLS_CIPHER_SUITE_UNKNOWN; 
                UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, cipher_suite));
                msg->cipher_suites.push_back(cipher_suite);
            }
        } while(0);

        // Unpack compression methods.
        do {
            uint8_t len = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, len));
            for (uint8_t i = 0; i < len; i++) {
                compression_method_type compression_method = 0;
                UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, compression_method));
                msg->compression_methods.push_back(compression_method);
            }
        } while(0);

        // Unpack extensions length.
        uint16_t extensions_len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extensions_len));
        if (end < p + extensions_len) {
            return -1;
        }

        const uint8_t *extensions_end = p + extensions_len;
        while (p < extensions_end) {
            extension_type extension_type = -1;
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extension_type));
            uint16_t extension_len = 0; 
            UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, extension_len));
            switch (extension_type) {
            case TLS_EXTENSION_SERVER_NAME:
                for (const uint8_t *end = p + extension_len; p < end;) {
                    uint16_t len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, len));
                    uint8_t name_type = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, name_type));
                    uint16_t name_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, name_len));
                    if (end < p + name_len) {
                        return -1;
                    }
                    std::string name;
                    UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, name, name_len));
                    if (name_type == 0) {
                        msg->server_name = std::move(name);
                    }
                }
                break;
            case TLS_EXTENSION_STATUS_REQUEST:
                {
                    uint8_t status_type = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, status_type));
                    uint16_t ignored_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, ignored_len));
                    if (ignored_len > 0) {
                        std::string ignored;
                        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, ignored, (int32_t)ignored_len));
                    }
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, ignored_len));
                    if (ignored_len > 0) {
                        std::string ignored;
                        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, ignored, (int32_t)ignored_len));
                    }
                    if (status_type == 1) {
                        msg->is_support_ocsp_stapling = true;
                    }
                }
                break;
            case TLS_EXTENSION_SUPPORTED_GROUPS:
                {
                    uint16_t groups_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, groups_len));
                    if (extension_len != groups_len + 2) {
                        return -1;
                    }
                    for (uint16_t i = groups_len; i > 0; i -= 2) {
                        ssl::curve_type group_type = ssl::TLS_CURVE_UNKNOWN;
                        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, group_type));
                        msg->supported_groups.push_back(group_type);
                    }
                }
                break;
            case TLS_EXTENSION_SUPPORTED_POINTS:
                {
                    uint8_t points_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, points_len));
                    if (extension_len != points_len + 1) {
                        return -1;
                    }
                    for (uint8_t i = points_len; i > 0; i--) {
                        point_format_type point_type = TLS_POINT_FORMAT_UNCOMPRESSED;
                        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, point_type));
                        msg->supported_points.push_back(point_type);
                    }
                }
                break;
            case TLS_EXTENSION_SESSION_TICKET:
                if (extension_len > 0) {
                    msg->is_support_session_ticket = true;
                    UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->session_ticket, (int32_t)extension_len));
                }
                break;
            case TLS_EXTENSION_SIGNATURE_ALGORITHMS:
                {
                    uint16_t schemes_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, schemes_len));
                    if (extension_len != schemes_len + 2) {
                        return -1;
                    }
                    for (uint16_t i = schemes_len; i > 0; i -= 2) {
                        ssl::signature_scheme scheme = ssl::TLS_SIGN_SCHE_UNKNOWN;
                        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, scheme));
                        msg->supported_signature_schemes.push_back(scheme);
                    }
                }
                break;
            case TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT:
                {
                    uint16_t certs_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, certs_len));
                    if (extension_len != certs_len + 2) {
                        return -1;
                    }
                    for (uint16_t i = certs_len; i > 0; i -= 2) {
                        uint16_t cert_type = 0;
                        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, cert_type));
                        msg->supported_signature_scheme_certs.push_back(cert_type);
                    }
                }
                break;
            case TLS_EXTENSION_RENEGOTIATION_INFO:
                {
                    uint8_t info_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, info_len));
                    if (extension_len != info_len + 1) {
                        return -1;
                    }
                    if (info_len > 0) {
                        msg->is_support_renegotiation_info = true;
                        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->renegotiation_info, (int32_t)info_len));
                    }
                }
                break;
            case TLS_EXTENSION_ALPN:
                {
                    uint16_t alpns_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, alpns_len));
                    if (extension_len != alpns_len + 2) {
                        return -1;
                    }
                    while(alpns_len > 0) {
                        uint8_t alpn_len = 0;
                        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, alpn_len));
                        if (alpn_len == 0 || alpns_len < (uint16_t)alpn_len - 1) {
                            return -1;
                        }
                        std::string alpn;
                        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, alpn, (int32_t)alpn_len));
                        msg->alpns.push_back(std::move(alpn));
                        alpns_len -= uint16_t(1 + alpn_len);
                    }
                }
                break;
            case TLS_EXTENSION_SCT:
                msg->is_support_scts = true;
                break;
            case TLS_EXTENSION_SUPPORTED_VERSIONS:
                {
                    uint8_t versions_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, versions_len));
                    if (extension_len != uint16_t(versions_len + 1)) {
                        return -1;
                    }
                    for (uint8_t i = 0; i < versions_len; i += 2) {
                        version_type version = TLS_VERSION_UNKNOWN;
                        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, version));
                        msg->supported_versions.push_back(version);
                    }
                }
                break;
            case TLS_EXTENSION_COOKIE:
                {
                    uint16_t cookie_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, cookie_len));
                    if (extension_len != cookie_len + 2) {
                        return -1;
                    }
                    UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->cookie, (int32_t)cookie_len));
                }
                break;
            case TLS_EXTENSION_KEY_SHARE:
                {
                    uint16_t key_shares_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, key_shares_len));
                    if (extension_len != uint16_t(key_shares_len + 2)) {
                        return -1;
                    }
                    while(key_shares_len > 0) {
                        key_share key_share;
                        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, key_share.group));
                        uint16_t key_share_len = 0;
                        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, key_share_len));
                        if (key_shares_len < 2 + 2 + key_share_len) {
                            return -1;
                        }
                        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, key_share.data, (int32_t)key_share_len));
                        msg->key_shares.push_back(std::move(key_share));
                        key_shares_len -= (2 + 2 + key_share_len);
                    }
                }  
                break;
            case TLS_EXTENSION_EARLY_DATA:
                msg->is_support_early_data = true;
                break;
            case TLS_EXTENSION_PSK_MODES:
                {
                    uint8_t psk_modes_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, psk_modes_len));
                    if (extension_len != uint16_t(psk_modes_len + 2)) {
                        return -1;
                    }
                    for (uint8_t i = 0; i < psk_modes_len; i++) {
                        uint8_t psk_mode = 0;
                        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, psk_mode));
                        msg->psk_modes.push_back(psk_mode);
                    }
                }
                break;
            case TLS_EXTENSION_PRE_SHARED_KEY:
                {
                    uint16_t psk_identities_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, psk_identities_len));
                    for (uint16_t i = psk_identities_len; i > 0;) {
                        uint16_t psk_identity_len = 0;
                        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, psk_identity_len));
                        if (i < (2 + psk_identity_len + 4)) {
                            return -1;
                        }
                        psk_identity psk_identity;
                        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, psk_identity.identity, (int32_t)psk_identity_len));
                        UNPACK_AND_RETURN_ERR(__unpack_uint32(p, end, psk_identity.obfuscated_ticket_age));
                        i -= (2 + psk_identity_len + 4);
                    }
                    uint16_t psk_binders_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, psk_binders_len));
                    for (uint16_t i = psk_binders_len; i > 0;) {
                        uint8_t psk_biner_len = 0;
                        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, psk_biner_len));
                        if (i < uint16_t(1 + psk_biner_len)) {
                            return -1;
                        }
                        std::string psk_binder;
                        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, psk_binder, (int32_t)psk_biner_len));
                        msg->psk_binders.push_back(std::move(psk_binder));
                        i -= uint16_t(1 + psk_biner_len);
                    }
                }
                break;
            default:
                {
                    extension additional_extension;
                    additional_extension.type = extension_type;
                    UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, additional_extension.data, (int32_t)extension_len));
                    msg->additional_extensions.push_back(std::move(additional_extension));
                }
                break;
            }
        }

        return int32_t(p - buf);
    }

    int32_t pack_server_hello(const server_hello_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_SERVER_HELLO));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Pack server tls version with 2 bytes.
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->legacy_version));

        // Pack random with 32 bytes.
        PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->random, 32));

        // Pack session id.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->session_id.size()));
        if (!msg->session_id.empty()) {
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->session_id));
        }

        // Pack cipher suite.
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->cipher_suite));

        // Pack compression method.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, msg->compression_method));
        
        // Skip to pack extensions length with 2 bytes.
        uint8_t *extension_len = p; p += 2;

        if (msg->is_support_ocsp_stapling) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_STATUS_REQUEST));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 0));
        }

        if (msg->is_support_session_ticket) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SESSION_TICKET));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 0));
        }

        if (msg->is_support_renegotiation_info) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_RENEGOTIATION_INFO));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + msg->renegotiation_info.size())));
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->renegotiation_info.size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->renegotiation_info));
        }

        if (!msg->alpn.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_ALPN));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + 1 + msg->alpn.size())));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(1 + msg->alpn.size())));
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->alpn.size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->alpn));
        }

        if (!msg->scts.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SCT));
            uint8_t *len = p; p += 2 * 2;
            for (int32_t i = 0; i < (int32_t)msg->scts.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->scts[i].size()));
                PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->scts[i]));
            }
            __pack_uint16(len, p, uint16_t(p - len - 2));
            __pack_uint16(len + 2, p, uint16_t(p - len - 4));
        }

        if (msg->supported_version != 0) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SUPPORTED_VERSIONS));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 2));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->supported_version));
        }

        if (msg->has_selected_key_share) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_KEY_SHARE));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + 2 + msg->selected_key_share.data.size())));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->selected_key_share.group));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->selected_key_share.data.size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->selected_key_share.data));
        }

        if (msg->selected_group != 0) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_KEY_SHARE));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 2));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->selected_group));
        }

        if (msg->has_selected_psk_identity) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_PRE_SHARED_KEY));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 2));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->selected_psk_identity));
        }

        if (!msg->cookie.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_COOKIE));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + msg->cookie.size())));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->cookie.size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->cookie));
        }

        // Pack supported point formats extenion.
        if (!msg->supported_points.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SUPPORTED_POINTS));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(1 + msg->supported_points.size() * 2)));
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->supported_points.size()));
            for (int32_t i = 0; i < (int32_t)msg->supported_points.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint8(p, end, msg->supported_points[i]));
            }
        }

        // Pack extensions length.
        __pack_uint16(extension_len, p, uint16_t(p - extension_len - 2));

        // Pack payload length.
        __pack_uint24(payload_len, p, uint16_t(p - payload_len - 3));

        return int32_t(p - buf);
    }

    int32_t unpack_server_hello(const uint8_t *buf, int32_t size, server_hello_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_SERVER_HELLO) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        // Unpack client tls version.
        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, msg->legacy_version));

        // Unpack random with 32 bytes.
        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->random, 32));

        // Unpack session id.
        do {
            uint8_t len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, len));
            if (len > 0) {
                UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->session_id, (int32_t)len));
            }
        } while(0);

        // Unpack cipher suite.
        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, msg->cipher_suite));

        // Unpack compression method.
        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, msg->compression_method));

        // Unpack extensions length.
        uint16_t extensions_len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extensions_len));
        if (end < p + extensions_len) {
            return -1;
        }

        const uint8_t *extensions_end = p + extensions_len;
        while (p < extensions_end) {
            uint16_t extension_type = -1;
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extension_type));
            uint16_t extension_len = 0; 
            UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, extension_len));
            switch (extension_type) {
            case TLS_EXTENSION_STATUS_REQUEST:
                msg->is_support_ocsp_stapling = true;
                break;
            case TLS_EXTENSION_SESSION_TICKET:
                msg->is_support_session_ticket = true;
                break;
            case TLS_EXTENSION_RENEGOTIATION_INFO:
                {
                    uint8_t info_len = 0;
                    UNPACK_AND_RETURN_ERR( __unpack_uint8(p, end, info_len));
                    UNPACK_AND_RETURN_ERR( __unpack_bytes(p, end, msg->renegotiation_info, (int32_t)info_len));
                    msg->is_support_renegotiation_info = true;
                }
                break;
            case TLS_EXTENSION_ALPN:
                {
                    uint16_t alpns_len = 0;
                    UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, alpns_len));
                    uint8_t alpn_len = 0;
                    UNPACK_AND_RETURN_ERR( __unpack_uint8(p, end, alpn_len));
                    UNPACK_AND_RETURN_ERR( __unpack_bytes(p, end, msg->alpn, (int32_t)alpn_len));
                }
                break;
            case TLS_EXTENSION_SCT:
                {
                    uint16_t scts_len = 0;
                    UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, scts_len));
                    while(scts_len > 0) {
                        uint16_t sct_len = 0;
                        UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, sct_len));
                        if (scts_len < 2 + sct_len) { return -1; } 
                        scts_len -= (2 + sct_len);
                        std::string sct;
                        UNPACK_AND_RETURN_ERR( __unpack_bytes(p, end, sct, (int32_t)sct_len));
                        msg->scts.push_back(std::move(sct));
                    }
                }
                break;
            case TLS_EXTENSION_SUPPORTED_VERSIONS:
                UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, msg->supported_version));
                break;
            case TLS_EXTENSION_COOKIE:
                {
                    uint16_t cookie_len = 0;
                    UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, cookie_len));
                    UNPACK_AND_RETURN_ERR( __unpack_bytes(p, end, msg->cookie, (int32_t)cookie_len));
                }
                break;
            case TLS_EXTENSION_KEY_SHARE:
                if (extensions_len == 2) {
                    UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, msg->selected_group));
                } else {
                    UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, msg->selected_key_share.group));
                    uint16_t len = 0;
                    UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, len));
                    UNPACK_AND_RETURN_ERR( __unpack_bytes(p, end, msg->selected_key_share.data, (int32_t)len));
                    msg->has_selected_key_share = true;
                }
                break;
            case TLS_EXTENSION_PRE_SHARED_KEY:
                UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, msg->selected_psk_identity));
                msg->has_selected_psk_identity = true;
                break;
            case TLS_EXTENSION_SUPPORTED_POINTS:
                {
                    uint8_t points_len = 0;
                    UNPACK_AND_RETURN_ERR( __unpack_uint8(p, end, points_len));
                    for (uint8_t i = 0; i < points_len; i++) {
                        point_format_type point_type = 0;
                        UNPACK_AND_RETURN_ERR( __unpack_uint8(p, end, point_type));
                        msg->supported_points.push_back(point_type);
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

    int32_t pack_new_session_ticket(const new_session_ticket_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_NEW_SESSION_TICKET));

        // Pack payload length.
        PACK_AND_RETURN_ERR(__pack_uint24(p, end, uint32_t(4 + 2 + msg->ticket.size())));

        // Pack lifetime hint.
        PACK_AND_RETURN_ERR(__pack_uint32(p, end, msg->lifetime_hint));

        // Pack ticket.
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->ticket.size()));
        PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->ticket));

        return int32_t(p - buf);
    }

    int32_t unpack_new_session_ticket(const uint8_t *buf, int32_t size, new_session_ticket_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_NEW_SESSION_TICKET) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        // Unpack lifetime hint.
        UNPACK_AND_RETURN_ERR(__unpack_uint32(p, end, msg->lifetime_hint));

        // Unpack ticket.
        uint16_t ticket_len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, ticket_len));
        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->ticket, (uint32_t)ticket_len));

        return int32_t(p - buf);
    }

    int32_t pack_new_session_ticket_tls13(const new_session_ticket_tls13_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_NEW_SESSION_TICKET));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Pack ticket lifetime.
        PACK_AND_RETURN_ERR(__pack_uint32(p, end, msg->lifetime));

        // Pack ticket age add time.
        PACK_AND_RETURN_ERR(__pack_uint32(p, end, msg->age_add));

        // Pack ticket nonce.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->nonce.size()));
        if (!msg->nonce.empty()) {
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->nonce));
        }

        // Pack ticket lable.
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->label.size()));
        if (!msg->label.empty()) {
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->label));
        }

        // Pack extensions.
        if (msg->max_early_data_size == 0) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 0));
        } else {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 8));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_EARLY_DATA));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 2));
            PACK_AND_RETURN_ERR(__pack_uint32(p, end, msg->max_early_data_size));
        }

        // Pack payload length.
        __pack_uint24(payload_len, p, uint16_t(p - payload_len - 3));

        return int32_t(p - buf);
    }

    int32_t unpack_new_session_ticket_tls13(const uint8_t *buf, int32_t size, new_session_ticket_tls13_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_NEW_SESSION_TICKET) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        // Unpack ticket lifetime.
        UNPACK_AND_RETURN_ERR(__unpack_uint32(p, end, msg->lifetime));

        // Unpack ticket age add time.
        UNPACK_AND_RETURN_ERR(__unpack_uint32(p, end, msg->age_add));

        // Unpack ticket nonce.
        uint8_t nonce_len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, nonce_len));
        if (nonce_len > 0) {
            UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->nonce, (int32_t)nonce_len));
        }

        // Unpack ticket lable.
        uint8_t lable_len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, lable_len));
        if (lable_len > 0) {
            UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->label, (int32_t)lable_len));
        }

        // Unpack extensions length.
        uint16_t extensions_len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extensions_len));
        if (end < p + extensions_len) {
            return -1;
        }

        // Unpack extensions.
        if (extensions_len > 0) {
            uint16_t extension_type = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extension_type));
            uint16_t extension_len = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extension_len));
            UNPACK_AND_RETURN_ERR(__unpack_uint32(p, end, msg->max_early_data_size));
        }

        return int32_t(p - buf);
    }

    int32_t pack_end_early_data(const end_early_data_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_END_OF_EARLY_DATA));

        // Pack payload length.
        PACK_AND_RETURN_ERR(__pack_uint24(p, end, 0));

        return int32_t(p - buf);  
    }

    int32_t unpack_end_early_data(const uint8_t *buf, int32_t size, end_early_data_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_END_OF_EARLY_DATA) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));
        if (payload_len != 0) {
            return -1;
        }

        return int32_t(p - buf);
    }

    int32_t pack_encrypted_extensions(const encrypted_extensions_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_ENCRYPTED_EXTENSIONS));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Skip to pack extensions length with 2 bytes.
        uint8_t *extension_len = p; p += 2;

        if (!msg->alpn.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_ALPN));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + 1 + msg->alpn.size())));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(1 + msg->alpn.size())));
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->alpn.size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->alpn)); 
        }

        if (msg->is_support_early_data) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_EARLY_DATA));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 0));
        }

        for (int32_t i = 0; i < (int32_t)msg->additional_extensions.size(); i++) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->additional_extensions[i].type));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->additional_extensions[i].data.size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->additional_extensions[i].data));
        }

        // Pack extensions length.
        __pack_uint16(extension_len, p, uint16_t(p - extension_len - 2));

        // Pack payload length.
        __pack_uint24(payload_len, p, uint16_t(p - payload_len - 3));

        return int32_t(p - buf);
    }

    int32_t unpack_encrypted_extensions(const uint8_t *buf, int32_t size, encrypted_extensions_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_ENCRYPTED_EXTENSIONS) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        // Unpack extensions length.
        uint16_t extensions_len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extensions_len));
        if (end < p + extensions_len) {
            return -1;
        }

        const uint8_t *extensions_end = p + extensions_len;
        while (p < extensions_end) {
            uint16_t extension_type = -1;
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extension_type));
            uint16_t extension_len = 0; 
            UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, extension_len));
            switch (extension_type) {
            case TLS_EXTENSION_ALPN:
                {
                    uint16_t alpns_len = 0;
                    UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, alpns_len));
                    uint8_t alpn_len = 0;
                    UNPACK_AND_RETURN_ERR( __unpack_uint8(p, end, alpn_len));
                    UNPACK_AND_RETURN_ERR( __unpack_bytes(p, end, msg->alpn, (int32_t)alpn_len));
                }
                break;
            case TLS_EXTENSION_EARLY_DATA:
                msg->is_support_early_data = true;
                break;
            default:
                {
                    extension additional_extension;
                    additional_extension.type = extension_type;
                    UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, additional_extension.data, (int32_t)extension_len));
                    msg->additional_extensions.push_back(std::move(additional_extension));
                }
                break;
            }
        }

        return int32_t(p - buf); 
    }

    int32_t pack_certificate(const certificate_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_CERTIFICATE));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Skip to pack certificates length with 3 bytes.
        uint8_t *certificates_len = p; p += 3;

        // Pack certificates.
        for (int32_t i = 0; i < (int32_t)msg->certificates.size(); i++) {
            // Pack certificate.
            PACK_AND_RETURN_ERR(__pack_uint24(p, end, (uint32_t)msg->certificates[i].size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->certificates[i]));
        }

        // Pack certificates length.
        __pack_uint24(certificates_len, p, uint32_t(p - certificates_len - 3));

        // Pack payload length.
        __pack_uint24(payload_len, p, uint32_t(p - payload_len - 3));

        return int32_t(p - buf);
    }

    int32_t unpack_certificate(const uint8_t *buf, int32_t size, certificate_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CERTIFICATE) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        // Unpack certificates length.
        uint32_t certificates_len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, certificates_len));
        if (end < p + certificates_len) {
            return -1;
        }

        // Unpack certificates.
        const uint8_t *certificates_end = p + certificates_len;
        while (p < certificates_end) {
            uint32_t certificate_len = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint24(p, certificates_end, certificates_len));
            std::string certificate;
            UNPACK_AND_RETURN_ERR(__unpack_bytes(p, certificates_end, certificate, (int32_t)certificate_len));
            msg->certificates.push_back(std::move(certificate));
        }

        return int32_t(p - buf);
    }

    int32_t pack_certificate_tls13(const certificate_tls13_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_CERTIFICATE));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Pack certificate request context length.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, 0));

        // Skip to pack certificates length with 3 bytes.
        uint8_t *certificates_len = p; p += 3;

        // Pack certificates.
        for (int32_t i = 0; i < (int32_t)msg->certificates.size(); i++) {
            if (i > 0) {
                break;
            }

            // Pack certificate.
            PACK_AND_RETURN_ERR(__pack_uint24(p, end, (uint32_t)msg->certificates[i].size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->certificates[i]));

            // Skip to pack extensions length.
            uint8_t *extensions_len = p; p += 2;

            // Pack status request extension.
            if (msg->is_support_ocsp_stapling) {
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_STATUS_REQUEST));
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(4 + msg->ocsp_staple.size())));
                PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_OCSP_STATUS));
                PACK_AND_RETURN_ERR(__pack_uint24(p, end, (uint32_t)msg->ocsp_staple.size()));
                PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->ocsp_staple));
            }

            // Pack sct extension.
            if (msg->is_support_scts) {
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SCT));
                uint8_t *len = p; p += 2 * 2;
                for (int32_t ii = 0; ii < (int32_t)msg->scts.size(); ii++) {
                    PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->scts[i].size()));
                    PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->scts[i]));
                }
                __pack_uint16(len, p, uint16_t(p - len - 2));
                __pack_uint16(len + 2, p, uint16_t(p - len - 4));
            }

            // Pack extensions length.
            __pack_uint16(extensions_len, p, uint16_t(p - extensions_len - 2));
        }

        // Pack certificates length.
        __pack_uint24(certificates_len, p, uint32_t(p - certificates_len - 3));

        // Pack payload length.
        __pack_uint24(payload_len, p, uint32_t(p - payload_len - 3));

        return int32_t(p - buf);
    }

    int32_t unpack_certificate_tls13(const uint8_t *buf, int32_t size, certificate_tls13_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CERTIFICATE) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        // Unpack certificate request context length.
        uint8_t context_len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, context_len));

        // Unpack certificates length.
        uint32_t certificates_len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, certificates_len));
        if (end < p + certificates_len) {
            return -1;
        }

        // Unpack certificates.
        const uint8_t *certificates_end = p + certificates_len;
        while (p < certificates_end) {
            uint32_t certificate_len = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint24(p, certificates_end, certificate_len));
            std::string certificate;
            UNPACK_AND_RETURN_ERR(__unpack_bytes(p, certificates_end, certificate, (int32_t)certificate_len));

            uint16_t extensions_len = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, certificates_end, extensions_len));

            const uint8_t *extensions_end = p + extensions_len;
            if (certificates_end < extensions_end) {
                return -1;
            }

            if (msg->certificates.size() > 0) {
                p += extensions_len;
                continue;
            }

            while (p < extensions_end) {
                uint16_t extension_type = -1;
                UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extension_type));
                uint16_t extension_len = 0; 
                UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extension_len));
                switch (extension_type) {
                case TLS_EXTENSION_STATUS_REQUEST:
                    {
                        uint8_t status = 0;
                        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, status));
                        uint32_t ocsp_staple_len = 0;
                        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, ocsp_staple_len));
                        if (ocsp_staple_len > 0) {
                            UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->ocsp_staple, (int32_t)ocsp_staple_len)); 
                        }
                        msg->is_support_ocsp_stapling = true;
                    }
                    break;
                case TLS_EXTENSION_SCT:
                    {
                        uint16_t scts_len = 0;
                        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, scts_len));
                        while (scts_len > 0) {
                            uint16_t sct_len = 0;
                            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, sct_len));
                            if (sct_len > 0) {
                                std::string sct;
                                UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, sct, (int32_t)sct_len));
                                msg->scts.push_back(std::move(sct));
                            }
                            scts_len -= (2 + sct_len);
                        }
                        msg->is_support_scts = true;
                    }
                    break;
                default:
                    p += extension_len;
                    break;
                }
            }

            msg->certificates.push_back(std::move(certificate));
        }

        return int32_t(p - buf);
    }

    int32_t pack_server_key_exchange(const server_key_exchange_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_SERVER_KEY_EXCHANGE));

        // Pack payload length.
        PACK_AND_RETURN_ERR(__pack_uint24(p, end, (uint32_t)msg->key.size()));

        // Pack key.
        PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->key));

        return int32_t(p - buf);
    }

    int32_t unpack_server_key_exchange(const uint8_t *buf, int32_t size, server_key_exchange_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_SERVER_KEY_EXCHANGE) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        // Unpack key.
        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->key, (int32_t)payload_len));

        return int32_t(p - buf);
    }

    int32_t pack_certificate_request(const certificate_request_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_CERTIFICATE_REQUEST));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Pack certificate types.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->certificate_types.size()));
        for (int32_t i = 0; i < (int32_t)msg->certificate_types.size(); i++) {
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, msg->certificate_types[i]));
        }

        // Pack signature algorithms.
        if (msg->has_signature_algorithms) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(msg->supported_signature_algorithms.size() * 2)));
            for (int32_t i = 0; i < (int32_t)msg->supported_signature_algorithms.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->supported_signature_algorithms[i]));
            }
        }

        // Pack certificate authorities.
        uint8_t *certificate_authorities_len = p; p += 2;
        for (int32_t i = 0; i < (int32_t)msg->certificate_authorities.size(); i++) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->certificate_authorities[i].size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->certificate_authorities[i]));
        }
        __pack_uint16(certificate_authorities_len, end, uint16_t(p - certificate_authorities_len - 2));

        // Pack payload length.
        __pack_uint24(payload_len, end, uint32_t(p - payload_len - 2));

        return int32_t(p - buf);
    }

    int32_t unpack_certificate_request(const uint8_t *buf, int32_t size, certificate_request_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CERTIFICATE_REQUEST) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        // Unpack certificate types.
        uint16_t certificate_types_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, certificate_types_len));
        for (int32_t i = 0; i < (int32_t)msg->certificate_types.size(); i++) {
            uint8_t certificate_type = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, certificate_type));
            msg->certificate_types.push_back(certificate_type);
        }

        if (msg->has_signature_algorithms) {
            uint16_t signature_algorithms_len = 0; 
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, signature_algorithms_len));
            for (uint16_t i = signature_algorithms_len / 2; i > 0; i++) {
                uint16_t signature_algorithms = 0; 
                UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, signature_algorithms));
                msg->supported_signature_algorithms.push_back(signature_algorithms);
            }
        }

        // Unpack certificate authorities.
        uint16_t certificate_authorities_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, certificate_authorities_len));
        const uint8_t *certificate_authorities_end = p + certificate_authorities_len;
        while (p < certificate_authorities_end) {
            uint16_t certificate_authority_len = 0; 
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, certificate_authority_len));
            std::string certificate_authority;
            UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, certificate_authority, certificate_authority_len));
            msg->certificate_authorities.push_back(certificate_authority);
        }

        return int32_t(p - buf);
    }

    int32_t pack_certificate_request_tls13(const certificate_request_tls13_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_CERTIFICATE_REQUEST));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        // Pack certificate request context length.
        // SHALL be zero length unless used for post-handshake authentication.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, 0));

        // Skip to pack extensions length with 2 bytes.
        uint8_t *extension_len = p; p += 2;

        // Pack status request extension.
        if (msg->is_support_ocsp_stapling) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_STATUS_REQUEST));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 0));
        }

        // Pack sct extension.
        if (msg->is_support_scts) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SCT));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, 0));
        }

        // Pack signature algorithms extension.
        if (!msg->supported_signature_schemes.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SIGNATURE_ALGORITHMS));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + msg->supported_signature_schemes.size() * 2)));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(msg->supported_signature_schemes.size() * 2)));
            for (int32_t i = 0; i < (int32_t)msg->supported_signature_schemes.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->supported_signature_schemes[i]));
            }
        }

        // Pack signature algorithms certs extension.
        if (!msg->supported_signature_algorithms_certs.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + msg->supported_signature_algorithms_certs.size() * 2)));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(msg->supported_signature_algorithms_certs.size() * 2)));
            for (int32_t i = 0; i < (int32_t)msg->supported_signature_algorithms_certs.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->supported_signature_algorithms_certs[i]));
            }
        }

        // Pack signature algorithms certs extension.
        if (!msg->certificate_authorities.empty()) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_CERTIFICATE_AUTHORITIES));
            uint8_t *len = p; p += 2 * 2;
            for (int32_t i = 0; i < (int32_t)msg->certificate_authorities.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->certificate_authorities[i].size()));
                PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->certificate_authorities[i]));
            }
            __pack_uint16(len, p, uint16_t(p - len - 2));
            __pack_uint16(len + 2, p, uint16_t(p - len - 4));
        }

        // Pack extensions length.
        __pack_uint16(extension_len, p, uint16_t(p - extension_len - 2));

        // Pack payload length.
        __pack_uint24(payload_len, p, uint16_t(p - payload_len - 3));

        return int32_t(p - buf);
    }

    int32_t unpack_certificate_request_tls13(const uint8_t *buf, int32_t size, certificate_request_tls13_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CERTIFICATE_REQUEST) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        // Unpack certificate request context length.
        // SHALL be zero length unless used for post-handshake authentication.
        uint8_t context_len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, context_len));

        // Unpack extensions length.
        uint16_t extensions_len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extensions_len));
        if (end < p + extensions_len) {
            return -1;
        }

        const uint8_t *extensions_end = p + extensions_len;
        while (p < extensions_end) {
            uint16_t extension_type = -1;
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extension_type));
            uint16_t extension_len = 0; 
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extension_len));
            switch (extension_type) {
            case TLS_EXTENSION_STATUS_REQUEST:
                msg->is_support_ocsp_stapling = true;
                break;
            case TLS_EXTENSION_SCT:
                msg->is_support_scts = true;
                break;
            case TLS_EXTENSION_SIGNATURE_ALGORITHMS:
                {
                    uint16_t signature_schemes_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, signature_schemes_len));
                    for (uint16_t i = signature_schemes_len / 2; i > 0; i--) {
                        ssl::signature_scheme scheme = ssl::TLS_SIGN_SCHE_UNKNOWN;
                        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, scheme));
                        msg->supported_signature_schemes.push_back(scheme);
                    }
                }
                break;
            case TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT:
                {
                    uint16_t signature_algorithms_certs_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, signature_algorithms_certs_len));
                    for (uint16_t i = signature_algorithms_certs_len / 2; i > 0; i--) {
                        uint16_t signature_algorithms_cert = 0;
                        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, signature_algorithms_cert));
                        msg->supported_signature_algorithms_certs.push_back(signature_algorithms_cert);
                    }
                }
                break;
            case TLS_EXTENSION_CERTIFICATE_AUTHORITIES:
                {
                    uint16_t certificate_authorities_len = 0;
                    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, certificate_authorities_len));
                    while (certificate_authorities_len > 0) {
                        uint8_t certificate_authority_len = 0;
                        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, certificate_authority_len));
                        std::string certificate_authority;
                        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, certificate_authority, (int32_t)certificate_authority_len));
                        msg->certificate_authorities.push_back(std::move(certificate_authority));
                        certificate_authorities_len -= uint16_t(2 + certificate_authority_len);
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

    int32_t pack_server_hello_done(const server_hello_done_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_SERVER_HELLO_DONE));

        // Pack payload length.
        PACK_AND_RETURN_ERR(__pack_uint24(p, end, 0));

        return int32_t(p - buf);
    }

    int32_t unpack_server_hello_done(const uint8_t *buf, int32_t size, server_hello_done_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_SERVER_HELLO_DONE) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        return int32_t(p - buf);
    }

    int32_t pack_certificate_verify(const certificate_verify_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_CERTIFICATE_VERIFY));

        // Pack payload length.
        if (msg->has_signature_scheme) {
            PACK_AND_RETURN_ERR(__pack_uint24(p, end, uint16_t(2 + 2 + msg->signature.size())));
        } else {
            PACK_AND_RETURN_ERR(__pack_uint24(p, end, uint16_t(2 + msg->signature.size())));
        }
        
        if (msg->has_signature_scheme) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->signature_scheme));
        }

        // Pack signature data.
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->signature.size()));
        PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->signature));

        return int32_t(p - buf);
    }

    int32_t unpack_certificate_verify(const uint8_t *buf, int32_t size, certificate_verify_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CERTIFICATE_VERIFY) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        if (msg->has_signature_scheme) {
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, msg->signature_scheme));
        }

        uint16_t signature_len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, signature_len));
        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->signature, signature_len));

        return int32_t(p - buf);
    }

    int32_t pack_client_key_exchange(const client_key_exchange_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_CLIENT_KEY_EXCHANGE));

        // Pack payload length.
        PACK_AND_RETURN_ERR(__pack_uint24(p, end, (uint32_t)msg->ciphertext.size()));

        // Pack ciphertext.
        PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->ciphertext));

        return int32_t(p - buf);
    }

    int32_t unpack_client_key_exchange(const uint8_t *buf, int32_t size, client_key_exchange_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CLIENT_KEY_EXCHANGE) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        // Unpack ciphertext.
        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->ciphertext, (int32_t)payload_len));

        return int32_t(p - buf);
    }

    int32_t pack_finished(const finished_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_FINISHED));

        // Pack payload length.
        PACK_AND_RETURN_ERR(__pack_uint24(p, end, (uint32_t)msg->verify_data.size()));

        // Pack verify data.
        PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->verify_data));

        return int32_t(p - buf);
    }

    int32_t unpack_finished(const uint8_t *buf, int32_t size, finished_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_FINISHED) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        // Unpack verify data.
        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->verify_data, (int32_t)payload_len));

        return int32_t(p - buf);
    }

    int32_t pack_certificate_status(const certificate_status_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_CERTIFICATE_STATUS));

        // Pack payload length.
        PACK_AND_RETURN_ERR(__pack_uint24(p, end, uint32_t(1 + 3 + msg->response.size())));

        // Pack status.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_OCSP_STATUS));
        PACK_AND_RETURN_ERR(__pack_uint24(p, end, (uint32_t)msg->response.size()));
        PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->response));

        return int32_t(p - buf);
    }

    int32_t unpack_certificate_status(const uint8_t *buf, int32_t size, certificate_status_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_CERTIFICATE_STATUS) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

        // Unpack status.
        certicate_status_type status_type;
        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, status_type));
        uint32_t status_len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, status_len));
        UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->response, (int32_t)status_len));

        return int32_t(p - buf);
    }


    int32_t pack_key_update(const key_update_message *msg, uint8_t *buf, int32_t max_size) {
        uint8_t *p = buf;
        uint8_t *end = p + max_size;

        // Pack message type with 1 bytes.
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_KEY_UPDATE));

        // Skip to pack payload length with 3 bytes.
        uint8_t *payload_len = p; p += 3;

        if (msg->update_requested) {
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, 1));
        } else {
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, 0));
        }

        // Pack payload length.
        PACK_AND_RETURN_ERR(__pack_uint24(payload_len, end, 0));

        return int32_t(p - buf);
    }

    int32_t unpack_key_update(const uint8_t *buf, int32_t size, key_update_message *msg) {
        const uint8_t *p = buf;
        const uint8_t *end = buf + size;
        if (p[0] != TLS_MSG_KEY_UPDATE) {
            return -1;
        }
        p += 1;

        // Unpack payload length.
        uint32_t payload_len = 0; 
        UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));
        if (payload_len != 1) {
            return -1;
        }

        uint8_t update_requested = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, update_requested));
        msg->update_requested = (update_requested == 1);

        return int32_t(p - buf);
    }

    std::string pack_message_hash(const std::string &hash) {
        std::string data;
        data.push_back(TLS_MSG_MESSAGE_HASH);
        data.append(2, 0);
        data.push_back((int8_t)hash.size());
        data.append(hash);
        return std::forward<std::string>(data);
    }

#undef PACK_AND_RETURN_ERR

#undef UNPACK_AND_RETURN_ERR

}
}
}
}