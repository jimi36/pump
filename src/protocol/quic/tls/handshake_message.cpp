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
#include "pump/protocol/quic/tls/handshake_messages.h"

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
    val = uint32_t(*(p + 0) >> 16) |
          uint32_t(*(p + 1) >> 8) |
          uint32_t(*(p + 2)) ;
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

int32_t pack_client_hello(const client_hello_message *msg, uint8_t *buf, int32_t max_size) {
#define PACK_AND_RETURN_ERR(pack) \
    p = pack; \
    if (!p) { return -1; } void(0)

    uint8_t *p = buf;
    uint8_t *end = p + max_size;

    // Pack message type with 1 bytes.
    PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_CLIENT_HELLO));

    // Skip to pack payload length with 3 bytes.
    uint8_t *payload_len = p; p += 3;

    // Pack client tls version with 2 bytes.
    PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->client_version));

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
    if (msg->is_support_ocsp) {
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
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(1 + msg->supported_points.size() * 2)));
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
    if (!msg->supported_signature_algorithms.empty()) {
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SIGNATURE_ALGORITHMS));
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + msg->supported_signature_algorithms.size() * 2)));
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(msg->supported_signature_algorithms.size() * 2)));
        for (int32_t i = 0; i < (int32_t)msg->supported_signature_algorithms.size(); i++) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->supported_signature_algorithms[i]));
        }
    }

    // Pack supported signature algorithms certs extenion.
    if (!msg->supported_signature_algorithms_certs.empty()) {
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT));
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + msg->supported_signature_algorithms_certs.size() * 2)));
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(msg->supported_signature_algorithms_certs.size() * 2)));
        for (int32_t i = 0; i < (int32_t)msg->supported_signature_algorithms_certs.size(); i++) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->supported_signature_algorithms_certs[i]));
        }
    }

    // Pack renegotiation info extenion.
    if (msg->is_support_renegotiation_info) {
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_RENEGOTIATION_INFO));
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + msg->renegotiation_info.size())));
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->renegotiation_info.size()));
        PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->renegotiation_info));
    }

    // Pack application layer protocol negotiation extenion.
    if (!msg->alpns.empty()) {
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_ALPN));
        uint8_t *len = p; p += 2 * 2; if (end < p) { return -1; }
        for (int32_t i = 0; i < (int32_t)msg->alpns.size(); i++) {
            PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->alpns[i].size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->alpns[i]));
        }
        __pack_uint16(len, p, uint16_t(p - len - 2));
        __pack_uint16(len + 2, p, uint16_t(p - len - 4));
    }

    // Pack signed certificate timestamp extenion.
    if (msg->is_support_sct) {
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
        uint8_t *len = p; p += 2 * 2; if (end < p) { return -1; }
        for (int32_t i = 0; i <  (int32_t)msg->key_shares.size(); i++) {
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->key_shares[i].group));
            PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->key_shares[i].data.size()));
            PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->key_shares[i].data));
        }
        __pack_uint16(len, p, uint16_t(p - len - 2));
        __pack_uint16(len + 2, p, uint16_t(p - len - 2));
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
        uint8_t *len1 = p;
        {
            uint8_t *len2 = p + 2;
            p += 2 * 2; if (end < p) { return -1; }
            for (int32_t i = 0; i < (int32_t)msg->psk_identities.size(); i++) {
                PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->psk_identities[i].identity.size()));
                PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->psk_identities[i].identity));
                PACK_AND_RETURN_ERR(__pack_uint32(p, end, msg->psk_identities[i].obfuscated_ticket_age));
            }
            __pack_uint16(len2, p, uint16_t(p - len2 - 2));
        }
        {
            uint8_t *len2 = p; p += 2; if (end < p) { return -1; }

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

#undef PACK_AND_RETURN_ERR
}

int32_t unpack_client_hello(const uint8_t *buf, int32_t size, client_hello_message *msg) {
#define UNPACK_AND_RETURN_ERR(unpack) \
    p = unpack; \
    if (!p) { return -1; } void(0)

    const uint8_t *p = buf;
    const uint8_t *end = buf + size;
    if (p[0] != TLS_MSG_CLIENT_HELLO) {
        return -1;
    }

    // Unpack payload length.
    uint32_t payload_len = 0; 
    UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

    // Unpack client tls version.
    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, msg->client_version));

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
            uint16_t cipher_suite = 0; 
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, cipher_suite));
            msg->cipher_suites.push_back(cipher_suite);
        }
    } while(0);

    // Unpack compression methods.
    do {
        uint8_t len = 0;
        UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, len));
        for (uint8_t i = 0; i < len; i++) {
            uint8_t compression_method = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, compression_method));
            msg->compression_methods.push_back(compression_method);
        }
    } while(0);

    // Unpack extensions length.
    uint16_t extensions_len = 0;
    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extensions_len));
    if (size < extensions_len) {
        return -1;
    }

    const uint8_t *extensions_end = p + extensions_len;
    while (p < extensions_end) {
        uint16_t extension_type = -1;
        UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, extension_type));
        uint16_t extension_len = 0; 
        UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, extension_len));
        switch (extension_type) {
        case TLS_EXTENSION_SERVER_NAME:
            for (const uint8_t *end = p + extension_len; p < end;) {
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
                    break;
                }
            }
            break;
        case TLS_EXTENSION_STATUS_REQUEST:
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
                msg->is_support_ocsp = true;
            }
            break;
        case TLS_EXTENSION_SUPPORTED_GROUPS:
            uint16_t groups_len = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, groups_len));
            if (extension_len != groups_len + 2) {
                return -1;
            }
            for (uint16_t i = groups_len; i > 0; i -= 2) {
                uint16_t group_type = 0;
                UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, group_type));
                msg->supported_groups.push_back(group_type);
            }
            break;
        case TLS_EXTENSION_SUPPORTED_POINTS:
            uint8_t points_len = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, points_len));
            if (extension_len != points_len + 1) {
                return -1;
            }
            for (uint8_t i = points_len; i > 0; i -= 2) {
                uint8_t point_type = 0;
                UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, point_type));
                msg->supported_points.push_back(point_type);
            }
            break;
        case TLS_EXTENSION_SESSION_TICKET:
            if (extension_len > 0) {
                msg->is_support_session_ticket = true;
                UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->session_ticket, (int32_t)extension_len));
            }
            break;
        case TLS_EXTENSION_SIGNATURE_ALGORITHMS:
            uint16_t algorithms_len = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, algorithms_len));
            if (extension_len != algorithms_len + 2) {
                return -1;
            }
            for (uint16_t i = algorithms_len; i > 0; i -= 2) {
                uint16_t algorithms_type = 0;
                UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, algorithms_type));
                msg->supported_signature_algorithms.push_back(algorithms_type);
            }
            break;
        case TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT:
            uint16_t certs_len = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, certs_len));
            if (extension_len != certs_len + 2) {
                return -1;
            }
            for (uint16_t i = certs_len; i > 0; i -= 2) {
                uint16_t cert_type = 0;
                UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, cert_type));
                msg->supported_signature_algorithms_certs.push_back(cert_type);
            }
            break;
        case TLS_EXTENSION_RENEGOTIATION_INFO:
            uint16_t info_len = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, info_len));
            if (extension_len != info_len + 2) {
                return -1;
            }
            if (info_len > 0) {
                msg->is_support_renegotiation_info = true;
                UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->renegotiation_info, (int32_t)info_len));
            }
            break;
        case TLS_EXTENSION_ALPN:
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
            break;
        case TLS_EXTENSION_SCT:
            msg->is_support_sct = true;
            break;
        case TLS_EXTENSION_SUPPORTED_VERSIONS:
            uint8_t versions_len = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint8(p, end, versions_len));
            if (extension_len != uint16_t(versions_len + 1)) {
                return -1;
            }
            for (uint8_t i = 0; i > versions_len; i++) {
                uint16_t version_type = 0;
                UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, version_type));
                msg->supported_versions.push_back(version_type);
            }
            break;
        case TLS_EXTENSION_COOKIE:
            uint16_t cookie_len = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, cookie_len));
            if (extension_len != cookie_len + 2) {
                return -1;
            }
            UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, msg->cookie, (int32_t)cookie_len));
            break;
        case TLS_EXTENSION_KEY_SHARE:
            uint16_t key_shares_len = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, key_shares_len));
            if (extension_len != uint16_t(key_shares_len + 2)) {
                return -1;
            }
            while(key_shares_len > 0) {
                handshake_key_share key_share;
                UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, key_share.group));
                uint16_t key_share_len = 0;
                UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, key_share_len));
                if (key_shares_len < 2 + 2 + key_share_len) {
                    return -1;
                }
                UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, key_share.data, (int32_t)key_share_len));
                msg->key_shares.push_back(key_share);
                key_shares_len -= (2 + 2 + key_share_len);
            }
            break;
        case TLS_EXTENSION_EARLY_DATA:
            msg->is_support_early_data = true;
            break;
        case TLS_EXTENSION_PSK_MODES:
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
            break;
        case TLS_EXTENSION_PRE_SHARED_KEY:
            uint16_t psk_identities_len = 0;
            UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, psk_identities_len));
            for (uint16_t i = psk_identities_len; i > 0;) {
                uint16_t psk_identity_len = 0;
                UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, psk_identity_len));
                if (i < (2 + psk_identity_len + 4)) {
                    return -1;
                }
                handshake_psk_identity psk_identity;
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
                msg->psk_binders.push_back(psk_binder);
                i -= uint16_t(1 + psk_biner_len);
            }
            break;
        default:
            extension additional_extension;
            additional_extension.type = extension_type;
            UNPACK_AND_RETURN_ERR(__unpack_bytes(p, end, additional_extension.data, (int32_t)extension_len));
            msg->additional_extensions.push_back(std::move(additional_extension));
        }
    }

    return int32_t(p - buf);

#undef UNPACK_AND_RETURN_ERR
}

int32_t pack_server_hello(const server_hello_message *msg, uint8_t *buf, int32_t max_size) {
#define PACK_AND_RETURN_ERR(pack) \
    p = pack; \
    if (!p) { return -1; } void(0)

    uint8_t *p = buf;
    uint8_t *end = p + max_size;

    // Pack message type with 1 bytes.
    PACK_AND_RETURN_ERR(__pack_uint8(p, end, TLS_MSG_SERVER_HELLO));

    // Skip to pack payload length with 3 bytes.
    uint8_t *payload_len = p; p += 3;

    // Pack server tls version with 2 bytes.
    PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->server_version));

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

    if (msg->is_support_ocsp) {
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
        PACK_AND_RETURN_ERR(__pack_uint8(p, end, (uint8_t)msg->alpn.size())));
        PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->renegotiation_info));
    }

    if (!msg->scts.empty()) {
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_SCT));
        uint8_t *len = p; p += 2 * 2; if (end < p) { return -1; }
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

    if (msg->selected_key_share) {
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_KEY_SHARE));
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, uint16_t(2 + 2 + msg->key_share.data.size())));
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->key_share.group));
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, (uint16_t)msg->key_share.data.size()));
        PACK_AND_RETURN_ERR(__pack_bytes(p, end, msg->key_share.data));
    }

    if (msg->selected_group != 0) {
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_KEY_SHARE));
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, 2));
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->selected_group));
    }

    if (msg->selected_psk_identity) {
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, TLS_EXTENSION_PRE_SHARED_KEY));
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, 2));
        PACK_AND_RETURN_ERR(__pack_uint16(p, end, msg->psk_identity));
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

#undef PACK_AND_RETURN_ERR
}

int32_t unpack_server_hello(const uint8_t *buf, int32_t size, server_hello_message *msg) {
#define UNPACK_AND_RETURN_ERR(unpack) \
    p = unpack; \
    if (!p) { return -1; } void(0)

    const uint8_t *p = buf;
    const uint8_t *end = buf + size;
    if (p[0] != TLS_MSG_CLIENT_HELLO) {
        return -1;
    }

    // Unpack payload length.
    uint32_t payload_len = 0; 
    UNPACK_AND_RETURN_ERR(__unpack_uint24(p, end, payload_len));

    // Unpack client tls version.
    UNPACK_AND_RETURN_ERR(__unpack_uint16(p, end, msg->server_version));

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
    if (size < extensions_len) {
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
            msg->is_support_ocsp = true;
            break;
        case TLS_EXTENSION_SESSION_TICKET:
            msg->is_support_session_ticket = true;
            break;
        case TLS_EXTENSION_RENEGOTIATION_INFO:
            uint8_t len = 0;
            UNPACK_AND_RETURN_ERR( __unpack_uint8(p, end, len));
            UNPACK_AND_RETURN_ERR( __unpack_bytes(p, end, msg->renegotiation_info, (int32_t)len));
            msg->is_support_renegotiation_info = true;
            break;
        case TLS_EXTENSION_ALPN:
            uint16_t len1 = 0;
            UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, len1));
            uint8_t len2 = 0;
            UNPACK_AND_RETURN_ERR( __unpack_uint8(p, end, len2));
            UNPACK_AND_RETURN_ERR( __unpack_bytes(p, end, msg->alpn, (int32_t)len2));
            break;
        case TLS_EXTENSION_SCT:
            uint16_t len = 0;
            UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, len));
            while(len > 0) {
                uint16_t sct_len = 0;
                UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, sct_len));
                if (len < 2 + sct_len) { return -1; } 
                std::string sct;
                UNPACK_AND_RETURN_ERR( __unpack_bytes(p, end, sct, (int32_t)sct_len));
                msg->scts.push_back(sct);
                len -= (2 + sct_len); 
            }
            break;
        case TLS_EXTENSION_SUPPORTED_VERSIONS:
            UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, msg->supported_version));
            break;
        case TLS_EXTENSION_COOKIE:
            uint16_t len = 0;
            UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, len));
            UNPACK_AND_RETURN_ERR( __unpack_bytes(p, end, msg->cookie, (int32_t)len));
            break;
        case TLS_EXTENSION_KEY_SHARE：
            if (extensions_len == 2) {
                UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, msg->selected_group));
            } else {
                UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, msg->key_share.group));
                uint16_t len = 0;
                UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, len));
                UNPACK_AND_RETURN_ERR( __unpack_bytes(p, end, msg->key_share.data, (int32_t)len));
                msg->selected_key_share = true;
            }
            break;
        case TLS_EXTENSION_PRE_SHARED_KEY:
            UNPACK_AND_RETURN_ERR( __unpack_uint16(p, end, msg->psk_identity));
            msg->selected_psk_identity = true;
            break;
        case TLS_EXTENSION_SUPPORTED_POINTS:
            uint8_t len = 0;
            UNPACK_AND_RETURN_ERR( __unpack_uint8(p, end, len));
            for (uint8_t i = 0; i < len; i++) {
                tls_point_format_type point_type = 0;
                UNPACK_AND_RETURN_ERR( __unpack_uint8(p, end, point_type));
                msg->supported_points.push_back(point_type);
            }
            break;
        default:
            p += extensions_len;
            break;
        }
    }

    return int32_t(p - buf); 

#undef UNPACK_AND_RETURN_ERR
}