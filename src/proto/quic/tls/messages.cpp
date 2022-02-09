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
#include "pump/proto/quic/utils.h"
#include "pump/proto/quic/tls/utils.h"
#include "pump/proto/quic/tls/messages.h"

namespace pump {
namespace proto {
namespace quic {
namespace tls {

static void __pack_i16(block_t *b, uint16_t val) {
    *(uint16_t *)b = transform_endian_i16(val);
}

static void __pack_i24(block_t *b, uint32_t val) {
    val = transform_endian_i32(val);
    memcpy(b, (block_t *)&val + 1, 3);
}

handshake_message *new_handshake_message(message_type tp) {
    auto msg = object_create<handshake_message>();
    if (msg == nullptr) {
        return nullptr;
    }

    msg->tp = tp;
    msg->msg = nullptr;

    switch (tp) {
    case TLS_MSG_HELLO_REQUEST:
        msg->msg = new_hello_req_message();
        break;
    case TLS_MSG_CLIENT_HELLO:
        msg->msg = new_client_hello_message();
        break;
    case TLS_MSG_SERVER_HELLO:
        msg->msg = new_server_hello_message();
        break;
    case TLS_MSG_NEW_SESSION_TICKET:
        msg->msg = new_new_session_ticket_tls13_message();
        break;
    case TLS_MSG_END_OF_EARLY_DATA:
        msg->msg = new_end_early_data_message();
        break;
    case TLS_MSG_ENCRYPTED_EXTENSIONS:
        msg->msg = new_encrypted_extensions_message();
        break;
    case TLS_MSG_CERTIFICATE:
        msg->msg = new_certificate_tls13_message();
        break;
    case TLS_MSG_SERVER_KEY_EXCHANGE:
        msg->msg = new_server_key_exchange_message();
        break;
    case TLS_MSG_CERTIFICATE_REQUEST:
        msg->msg = new_certificate_req_tls13_message();
        break;
    case TLS_MSG_SERVER_HELLO_DONE:
        msg->msg = new_server_hello_done_message();
        break;
    case TLS_MSG_CERTIFICATE_VERIFY:
        msg->msg = new_certificate_verify_message();
        break;
    case TLS_MSG_CLIENT_KEY_EXCHANGE:
        msg->msg = new_client_key_exchange_message();
        break;
    case TLS_MSG_FINISHED:
        msg->msg = new_finished_message();
        break;
    case TLS_MSG_CERTIFICATE_STATUS:
        msg->msg = new_certificate_status_message();
        break;
    case TLS_MSG_KEY_UPDATE:
        msg->msg = new_certificate_status_message();
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
        switch (msg->tp) {
        case TLS_MSG_HELLO_REQUEST:
            object_delete((hello_req_message *)msg->msg);
            break;
        case TLS_MSG_CLIENT_HELLO:
            object_delete((client_hello_message *)msg->msg);
            break;
        case TLS_MSG_SERVER_HELLO:
            object_delete((server_hello_message *)msg->msg);
            break;
        case TLS_MSG_NEW_SESSION_TICKET:
            object_delete((new_session_ticket_tls13_message *)msg->msg);
            break;
        case TLS_MSG_END_OF_EARLY_DATA:
            object_delete((end_early_data_message *)msg->msg);
            break;
        case TLS_MSG_ENCRYPTED_EXTENSIONS:
            object_delete((encrypted_extensions_message *)msg->msg);
            break;
        case TLS_MSG_CERTIFICATE:
            object_delete((certificate_tls13_message *)msg->msg);
            break;
        case TLS_MSG_SERVER_KEY_EXCHANGE:
            object_delete((server_key_exchange_message *)msg->msg);
            break;
        case TLS_MSG_CERTIFICATE_REQUEST:
            object_delete((certificate_req_tls13_message *)msg->msg);
            break;
        case TLS_MSG_SERVER_HELLO_DONE:
            object_delete((server_hello_done_message *)msg->msg);
            break;
        case TLS_MSG_CERTIFICATE_VERIFY:
            object_delete((certificate_verify_message *)msg->msg);
            break;
        case TLS_MSG_CLIENT_KEY_EXCHANGE:
            object_delete((client_key_exchange_message *)msg->msg);
            break;
        case TLS_MSG_FINISHED:
            object_delete((finished_message *)msg->msg);
            break;
        case TLS_MSG_CERTIFICATE_STATUS:
            object_delete((certificate_status_message *)msg->msg);
            break;
        case TLS_MSG_KEY_UPDATE:
            object_delete((key_update_message *)msg->msg);
            break;
        default:
            break;
        }
    }

    object_delete(msg);
}

bool pack_handshake_message(handshake_message *msg) {
    if (!msg->packed.empty()) {
        return true;
    }

    io_buffer *iob = io_buffer::create(4096);
    if (iob == nullptr) {
        return false;
    }

    bool ret = false;
    switch (msg->tp) {
    case TLS_MSG_HELLO_REQUEST:
        ret = pack_hello_req_message(msg->msg, iob);
        break;
    case TLS_MSG_CLIENT_HELLO:
        ret = pack_client_hello_message(msg->msg, iob);
        break;
    case TLS_MSG_SERVER_HELLO:
        ret = pack_server_hello_message(msg->msg, iob);
        break;
    case TLS_MSG_NEW_SESSION_TICKET:
        ret = pack_new_session_ticket_tls13_message(msg->msg, iob);
        break;
    case TLS_MSG_END_OF_EARLY_DATA:
        ret = pack_end_early_data_message(msg->msg, iob);
        break;
    case TLS_MSG_ENCRYPTED_EXTENSIONS:
        ret = pack_encrypted_extensions_message(msg->msg, iob);
        break;
    case TLS_MSG_CERTIFICATE:
        ret = pack_certificate_tls13_message(msg->msg, iob);
        break;
    case TLS_MSG_SERVER_KEY_EXCHANGE:
        ret = pack_server_key_exchange_message(msg->msg, iob);
        break;
    case TLS_MSG_CERTIFICATE_REQUEST:
        ret = pack_certificate_req_tls13_message(msg->msg, iob);
        break;
    case TLS_MSG_SERVER_HELLO_DONE:
        ret = pack_server_hello_done_message(msg->msg, iob);
        break;
    case TLS_MSG_CERTIFICATE_VERIFY:
        ret = pack_certificate_verify_message(msg->msg, iob);
        break;
    case TLS_MSG_CLIENT_KEY_EXCHANGE:
        ret = pack_client_key_exchange_message(msg->msg, iob);
        break;
    case TLS_MSG_FINISHED:
        ret = pack_finished_message(msg->msg, iob);
        break;
    case TLS_MSG_CERTIFICATE_STATUS:
        ret = pack_certificate_status_message(msg->msg, iob);
        break;
    case TLS_MSG_KEY_UPDATE:
        ret = pack_key_update_message(msg->msg, iob);
        break;
    default:
        break;
    }

    if (ret && iob->data() > 0) {
        msg->packed.assign(iob->data(), iob->size());
    }
    iob->unrefer();

    return ret;
}

bool unpack_handshake_message(io_buffer *iob, handshake_message *msg) {
    if (msg == nullptr || msg->msg == nullptr) {
        return false;
    }

    uint32_t size = iob->size();
    const block_t *iobb = iob->data();

    bool ret = false;
    switch (msg->tp) {
    case TLS_MSG_HELLO_REQUEST:
        ret = unpack_hello_req_message(iob, msg->msg);
        break;
    case TLS_MSG_CLIENT_HELLO:
        ret = unpack_client_hello_message(iob, msg->msg);
        break;
    case TLS_MSG_SERVER_HELLO:
        ret = unpack_server_hello_message(iob, msg->msg);
        break;
    case TLS_MSG_NEW_SESSION_TICKET:
        ret = unpack_new_session_ticket_tls13_message(iob, msg->msg);
        break;
    case TLS_MSG_END_OF_EARLY_DATA:
        ret = unpack_end_early_data_message(iob, msg->msg);
        break;
    case TLS_MSG_ENCRYPTED_EXTENSIONS:
        ret = unpack_encrypted_extensions_message(iob, msg->msg);
        break;
    case TLS_MSG_CERTIFICATE:
        ret = unpack_certificate_tls13_message(iob, msg->msg);
        break;
    case TLS_MSG_SERVER_KEY_EXCHANGE:
        ret = unpack_server_key_exchange_message(iob, msg->msg);
        break;
    case TLS_MSG_CERTIFICATE_REQUEST:
        ret = unpack_certificate_req_tls13_message(iob, msg->msg);
        break;
    case TLS_MSG_SERVER_HELLO_DONE:
        ret = unpack_server_hello_done_message(iob, msg->msg);
        break;
    case TLS_MSG_CERTIFICATE_VERIFY:
        ret = unpack_certificate_verify_message(iob, msg->msg);
        break;
    case TLS_MSG_CLIENT_KEY_EXCHANGE:
        ret = unpack_client_key_exchange_message(iob, msg->msg);
        break;
    case TLS_MSG_FINISHED:
        ret = unpack_finished_message(iob, msg->msg);
        break;
    case TLS_MSG_CERTIFICATE_STATUS:
        ret = unpack_certificate_status_message(iob, msg->msg);
        break;
    case TLS_MSG_KEY_UPDATE:
        ret = unpack_key_update_message(iob, msg->msg);
        break;
    default:
        break;
    }

    if (ret && size > iob->size()) {
        msg->packed.assign(iobb, size - iob->size());
    }

    return ret;
}

hello_req_message *new_hello_req_message() {
    return object_create<hello_req_message>();
}

bool pack_hello_req_message(void *msg, io_buffer *iob) {
    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_HELLO_REQUEST, iob)) {
        return false;
    }

    // Pack payload length.
    if (!write_i24_to_iob(0, iob)) {
        return false;
    }

    return true;
}

bool unpack_hello_req_message(io_buffer *iob, void *msg) {
    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_HELLO_REQUEST) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_size = 0;
    if (!read_i24_from_iob(iob, payload_size)) {
        return false;
    }

    return true;
}

client_hello_message *new_client_hello_message() {
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

bool pack_client_hello_message(void *msg, io_buffer *iob) {
    auto raw = (const client_hello_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_CLIENT_HELLO, iob)) {
        return false;
    }

    // Skip to pack payload length with 3 bytes.
    uint32_t payload_len_pos = iob->size();
    if (!write_i24_to_iob(0, iob)) {
        return false;
    }

    // Pack client tls version with 2 bytes.
    if (!write_i16_to_iob(raw->legacy_version, iob)) {
        return false;
    }

    // Pack random with 32 bytes.
    if (!iob->write((block_t *)raw->random, 32)) {
        return false;
    }

    // Pack session id.
    if (!write_i8_to_iob(raw->session_id.size(), iob)) {
        return false;
    }
    if (!raw->session_id.empty()) {
        if (!write_string_to_iob(raw->session_id, iob)) {
            return false;
        }
    }

    // Pack cipher suites.
    if (!write_i16_to_iob(raw->cipher_suites.size() * 2, iob)) {
        return false;
    }
    for (auto cs : raw->cipher_suites) {
        if (!write_i16_to_iob(cs, iob)) {
            return false;
        }
    }

    // Pack compression methods.
    if (!write_i8_to_iob(raw->compression_methods.size(), iob)) {
        return false;
    }
    for (auto method : raw->compression_methods) {
        if (!write_i8_to_iob(method, iob)) {
            return false;
        }
    }

    // Skip to pack extensions length with 2 bytes.
    uint32_t extension_len_pos = iob->size();
    if (!write_i16_to_iob(0, iob)) {
        return false;
    }

    // Pack server name extenion.
    if (!raw->server_name.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_SERVER_NAME, iob) ||
            !write_i16_to_iob(2 + 1 + 2 + raw->server_name.size(), iob) ||
            !write_i16_to_iob(1 + 2 + raw->server_name.size(), iob) ||
            !write_i8_to_iob(0, iob) ||  // name_type = host_name
            !write_i16_to_iob(raw->server_name.size(),
                              iob) ||  // server name length
            !write_string_to_iob(raw->server_name, iob)) {
            return false;
        }
    }

    // Pack ocsp extenion.
    if (raw->is_support_ocsp_stapling) {
        if (!write_i16_to_iob(TLS_EXTENSION_STATUS_REQUEST, iob) ||
            !write_i16_to_iob(5, iob) ||
            !write_i8_to_iob(1, iob) ||   // status_type = ocsp
            !write_i16_to_iob(0, iob) ||  // empty responder_id_list
            !write_i16_to_iob(0, iob)) {  // empty request_extensions
            return false;
        }
    }

    // Pack supported curve groups extenion.
    if (!raw->supported_groups.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_SUPPORTED_GROUPS, iob) ||
            !write_i16_to_iob(2 + raw->supported_groups.size() * 2, iob) ||
            !write_i16_to_iob(raw->supported_groups.size() * 2, iob)) {
            return false;
        }
        for (auto group : raw->supported_groups) {
            if (!write_i16_to_iob(group, iob)) {
                return false;
            }
        }
    }

    // Pack supported point formats extenion.
    if (!raw->supported_point_formats.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_SUPPORTED_POINTS, iob) ||
            !write_i16_to_iob(1 + raw->supported_point_formats.size(), iob) ||
            !write_i8_to_iob(raw->supported_point_formats.size(), iob)) {
            return false;
        }
        for (auto point : raw->supported_point_formats) {
            if (!write_i8_to_iob(point, iob)) {
                return false;
            }
        }
    }

    // Pack session ticket extenion.
    if (raw->is_support_session_ticket) {
        if (!write_i16_to_iob(TLS_EXTENSION_SESSION_TICKET, iob) ||
            !write_i16_to_iob(raw->session_ticket.size(), iob) ||
            !write_string_to_iob(raw->session_ticket, iob)) {
            return false;
        }
    }

    // Pack supported signature algorithms extenion.
    if (!raw->signature_schemes.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_SIGNATURE_ALGORITHMS, iob) ||
            !write_i16_to_iob(2 + raw->signature_schemes.size() * 2, iob) ||
            !write_i16_to_iob(raw->signature_schemes.size() * 2, iob)) {
            return false;
        }
        for (auto scheme : raw->signature_schemes) {
            if (!write_i16_to_iob(scheme, iob)) {
                return false;
            }
        }
    }

    // Pack supported signature algorithms certs extenion.
    if (!raw->signature_scheme_certs.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT, iob) ||
            !write_i16_to_iob(2 + raw->signature_scheme_certs.size() * 2, iob) ||
            !write_i16_to_iob(raw->signature_scheme_certs.size() * 2, iob)) {
            return false;
        }
        for (auto scheme_cert : raw->signature_scheme_certs) {
            if (!write_i16_to_iob(scheme_cert, iob)) {
                return false;
            }
        }
    }

    // Pack renegotiation info extenion.
    if (raw->is_support_renegotiation_info) {
        if (!write_i16_to_iob(TLS_EXTENSION_RENEGOTIATION_INFO, iob) ||
            !write_i16_to_iob(1 + raw->renegotiation_info.size(), iob) ||
            !write_i8_to_iob(raw->renegotiation_info.size(), iob) ||
            !write_string_to_iob(raw->renegotiation_info, iob)) {
            return false;
        }
    }

    // Pack application layer proto negotiation extenion.
    if (!raw->alpns.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_ALPN, iob)) {
            return false;
        }
        uint32_t len_pos = iob->size();
        if (!iob->write(nullptr, 4)) {
            return false;
        }
        for (auto &alpn : raw->alpns) {
            if (!write_i8_to_iob(alpn.size(), iob) || !write_string_to_iob(alpn, iob)) {
                return false;
            }
        }
        uint16_t len = iob->size() - len_pos - 2;
        __pack_i16((block_t *)iob->data() + len_pos, len);
        __pack_i16((block_t *)iob->data() + len_pos + 2, len - 2);
    }

    // Pack signed certificate timestamp extenion.
    if (raw->is_support_scts) {
        if (!write_i16_to_iob(TLS_EXTENSION_SCT, iob) ||
            !write_i16_to_iob(0, iob)) {  // empty extension_data
            return false;
        }
    }

    // Pack supported versions extenion.
    if (!raw->supported_versions.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_SUPPORTED_VERSIONS, iob) ||
            !write_i16_to_iob(1 + raw->supported_versions.size() * 2, iob) ||
            !write_i8_to_iob(raw->supported_versions.size() * 2, iob)) {
            return false;
        }
        for (auto version : raw->supported_versions) {
            if (!write_i16_to_iob(version, iob)) {
                return false;
            }
        }
    }

    // Pack cookie extenion.
    if (!raw->cookie.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_COOKIE, iob) ||
            !write_i16_to_iob(2 + raw->cookie.size(), iob) ||
            !write_i16_to_iob(raw->cookie.size(), iob) ||
            !write_string_to_iob(raw->cookie, iob)) {
            return false;
        }
    }

    // Pack key shares extenion.
    if (!raw->key_shares.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_KEY_SHARE, iob)) {
            return false;
        }
        uint32_t len_pos = iob->size();
        if (!iob->write(nullptr, 4)) {
            return false;
        }
        for (auto &ks : raw->key_shares) {
            if (!write_i16_to_iob(ks.group, iob) ||
                !write_i16_to_iob(ks.data.size(), iob) ||
                !write_string_to_iob(ks.data, iob)) {
                return false;
            }
        }
        uint16_t len = iob->size() - len_pos - 2;
        __pack_i16((block_t *)iob->data() + len_pos, len);
        __pack_i16((block_t *)iob->data() + len_pos + 2, len - 2);
    }

    // Pack early data extenion.
    if (raw->is_support_early_data) {
        if (!write_i16_to_iob(TLS_EXTENSION_EARLY_DATA, iob) ||
            !write_i16_to_iob(0, iob)) {  // empty extension_data
            return false;
        }
    }

    // Pack psk modes extenion.
    if (!raw->psk_modes.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_PSK_MODES, iob) ||
            !write_i16_to_iob(1 + raw->psk_modes.size(), iob) ||
            !write_i8_to_iob(raw->psk_modes.size(), iob)) {
            return false;
        }
        for (auto mode : raw->psk_modes) {
            if (!write_i8_to_iob(mode, iob)) {
                return false;
            }
        }
    }

    // Pack additional extensions.
    for (auto &extension : raw->additional_extensions) {
        if (!write_i16_to_iob(extension.type, iob) ||
            !write_i16_to_iob(extension.data.size(), iob) ||
            !write_string_to_iob(extension.data, iob)) {
            return false;
        }
    }

    // Pack psk identities extenion.
    if (!raw->psk_identities.empty()) {  // Must serizlize the extenion at last.
        if (!write_i16_to_iob(TLS_EXTENSION_PRE_SHARED_KEY, iob)) {
            return false;
        }
        uint32_t len_pos = iob->size();
        if (!iob->write(nullptr, 2)) {
            return false;
        }
        {
            uint32_t llen_pos = iob->size();
            if (!iob->write(nullptr, 2)) {
                return false;
            }
            for (auto &id : raw->psk_identities) {
                if (!write_i16_to_iob(id.identity.size(), iob) ||
                    !write_string_to_iob(id.identity, iob) ||
                    !write_i32_to_iob(id.obfuscated_ticket_age, iob)) {
                    return false;
                }
            }
            uint16_t len = iob->size() - llen_pos - 2;
            __pack_i16((block_t *)iob->data() + llen_pos, len);
        }
        {
            uint32_t llen_pos = iob->size();
            if (!iob->write(nullptr, 2)) {
                return false;
            }
            for (auto &binder : raw->psk_binders) {
                if (!write_i8_to_iob(binder.size(), iob) ||
                    !write_string_to_iob(binder, iob)) {
                    return false;
                }
            }
            uint16_t len = iob->size() - llen_pos - 2;
            __pack_i16((block_t *)iob->data() + llen_pos, len);
        }
        uint16_t len = iob->size() - len_pos - 2;
        __pack_i16((block_t *)iob->data() + len_pos, len);
    }

    // Pack extensions length.
    uint16_t extension_len = iob->size() - extension_len_pos - 2;
    __pack_i16((block_t *)iob->data() + extension_len_pos, extension_len);

    // Pack payload length.
    uint32_t payload_len = iob->size() - payload_len_pos - 3;
    __pack_i24((block_t *)iob->data() + payload_len_pos, payload_len);

    return true;
}

bool unpack_client_hello_message(io_buffer *iob, void *msg) {
    auto raw = (client_hello_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_CLIENT_HELLO) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_len = 0;
    if (!read_i24_from_iob(iob, payload_len)) {
        return false;
    }

    // Unpack client tls version.
    if (!read_i16_from_iob(iob, raw->legacy_version)) {
        return false;
    }

    // Unpack random with 32 bytes.
    if (!iob->read((block_t *)raw->random, 32)) {
        return false;
    }

    // Unpack session id.
    do {
        uint8_t len = 0;
        if (!read_i8_from_iob(iob, len)) {
            return false;
        } else if (len > 0) {
            raw->session_id.resize(len);
            if (!read_string_from_iob(iob, raw->session_id)) {
                return false;
            }
        }
    } while (0);

    // Unpack cipher suites.
    do {
        uint16_t len = 0;
        if (!read_i16_from_iob(iob, len)) {
            return false;
        }
        for (uint16_t i = 0; i < len; i += 2) {
            cipher_suite_type cipher_suite = TLS_CIPHER_SUITE_UNKNOWN;
            if (!read_i16_from_iob(iob, cipher_suite)) {
                return false;
            }
            raw->cipher_suites.push_back(cipher_suite);
        }
    } while (0);

    // Unpack compression methods.
    do {
        uint8_t len = 0;
        if (!read_i8_from_iob(iob, len)) {
            return false;
        }
        for (uint8_t i = 0; i < len; i++) {
            compression_method_type compression_method = 0;
            if (!read_i8_from_iob(iob, compression_method)) {
                return false;
            }
            raw->compression_methods.push_back(compression_method);
        }
    } while (0);

    // Unpack extensions length.
    uint16_t extensions_len = 0;
    if (!read_i16_from_iob(iob, extensions_len)) {
        return false;
    } else if (iob->size() < extensions_len) {
        return false;
    }

    auto ex_iob = io_buffer::create();
    auto exs_iob = io_buffer::create_by_refence(iob->data(), extensions_len);
    while (exs_iob->size() > 0) {
        extension_type extension_type = -1;
        uint16_t extension_len = 0;
        if (!read_i16_from_iob(exs_iob, extension_type) ||
            !read_i16_from_iob(exs_iob, extension_len)) {
            break;
        }

        if (exs_iob->size() < extension_len) {
            break;
        } else if (!ex_iob->reset_by_reference(exs_iob->data(), extension_len)) {
            break;
        }

        switch (extension_type) {
        case TLS_EXTENSION_SERVER_NAME:
            while (ex_iob->size() > 0) {
                uint16_t len = 0;
                if (!read_i16_from_iob(ex_iob, len)) {
                    break;
                }
                uint8_t name_tp = 0;
                uint16_t name_len = 0;
                if (!read_i8_from_iob(ex_iob, name_tp) ||
                    !read_i16_from_iob(ex_iob, name_len)) {
                    break;
                }
                if (name_len > 0) {
                    if (name_tp == 0) {
                        raw->server_name.resize(name_len);
                        if (!read_string_from_iob(ex_iob, raw->server_name)) {
                            break;
                        }
                    } else if (ex_iob->shift(name_len) < 0) {
                        break;
                    }
                }
            }
            break;
        case TLS_EXTENSION_STATUS_REQUEST: {
            uint8_t status_type = 0;
            if (!read_i8_from_iob(ex_iob, status_type)) {
                break;
            }
            raw->is_support_ocsp_stapling = (status_type == 1);

            uint16_t ignored_len = 0;
            if (!read_i16_from_iob(iob, ignored_len) || ex_iob->shift(ignored_len) < 0) {
                break;
            }
            if (!read_i16_from_iob(iob, ignored_len) || ex_iob->shift(ignored_len) < 0) {
                break;
            }
        } break;
        case TLS_EXTENSION_SUPPORTED_GROUPS: {
            uint16_t groups_len = 0;
            if (!read_i16_from_iob(ex_iob, groups_len)) {
                break;
            }
            while (ex_iob->size() > 0) {
                ssl::curve_group_type group_type = ssl::TLS_CURVE_UNKNOWN;
                if (!read_i16_from_iob(ex_iob, group_type)) {
                    break;
                }
                raw->supported_groups.push_back(group_type);
            }
        } break;
        case TLS_EXTENSION_SUPPORTED_POINTS: {
            uint8_t points_len = 0;
            if (!read_i8_from_iob(ex_iob, points_len)) {
                break;
            }
            while (ex_iob->size() > 0) {
                point_format_type point_type = TLS_POINT_FORMAT_UNCOMPRESSED;
                if (!read_i8_from_iob(ex_iob, point_type)) {
                    break;
                }
                raw->supported_point_formats.push_back(point_type);
            }
        } break;
        case TLS_EXTENSION_SESSION_TICKET:
            if (ex_iob->size() > 0) {
                raw->is_support_session_ticket = true;
                raw->session_ticket.resize(ex_iob->size());
                if (!read_string_from_iob(ex_iob, raw->session_ticket)) {
                    break;
                }
            }
            break;
        case TLS_EXTENSION_SIGNATURE_ALGORITHMS: {
            uint16_t schemes_len = 0;
            if (!read_i16_from_iob(ex_iob, schemes_len)) {
                break;
            }
            while (ex_iob->size() > 0) {
                ssl::signature_scheme scheme = ssl::TLS_SIGN_SCHE_UNKNOWN;
                if (!read_i16_from_iob(ex_iob, scheme)) {
                    break;
                }
                raw->signature_schemes.push_back(scheme);
            }
        } break;
        case TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT: {
            uint16_t certs_len = 0;
            if (!read_i16_from_iob(ex_iob, certs_len)) {
                break;
            }
            while (ex_iob->size() > 0) {
                uint16_t cert_type = 0;
                if (!read_i16_from_iob(ex_iob, cert_type)) {
                    break;
                }
                raw->signature_scheme_certs.push_back(cert_type);
            }
        } break;
        case TLS_EXTENSION_RENEGOTIATION_INFO: {
            uint8_t info_len = 0;
            if (!read_i8_from_iob(ex_iob, info_len)) {
                break;
            } else if (info_len > 0) {
                raw->renegotiation_info.resize(info_len);
                if (!read_string_from_iob(ex_iob, raw->renegotiation_info)) {
                    break;
                }
                raw->is_support_renegotiation_info = true;
            }
        } break;
        case TLS_EXTENSION_ALPN: {
            uint16_t alpns_len = 0;
            if (!read_i16_from_iob(ex_iob, alpns_len)) {
                break;
            }
            while (ex_iob->size() > 0) {
                uint8_t alpn_len = 0;
                if (!read_i8_from_iob(ex_iob, alpn_len)) {
                    break;
                } else if (ex_iob->size() != alpn_len) {
                    break;
                }
                std::string alpn(alpn_len, '\0');
                if (!read_string_from_iob(ex_iob, alpn)) {
                    break;
                }
                raw->alpns.push_back(std::move(alpn));
            }
        } break;
        case TLS_EXTENSION_SCT: {
            raw->is_support_scts = true;
        } break;
        case TLS_EXTENSION_SUPPORTED_VERSIONS: {
            uint8_t versions_len = 0;
            if (!read_i8_from_iob(ex_iob, versions_len)) {
                break;
            }
            while (ex_iob->size() > 0) {
                version_type version = TLS_VERSION_UNKNOWN;
                if (!read_i16_from_iob(ex_iob, version)) {
                    break;
                }
                raw->supported_versions.push_back(version);
            }
        } break;
        case TLS_EXTENSION_COOKIE: {
            uint16_t cookie_len = 0;
            if (!read_i16_from_iob(ex_iob, cookie_len)) {
                break;
            }
            raw->cookie.resize(cookie_len);
            if (!read_string_from_iob(ex_iob, raw->cookie)) {
                break;
            }
        } break;
        case TLS_EXTENSION_KEY_SHARE: {
            uint16_t key_shares_len = 0;
            if (!read_i16_from_iob(ex_iob, key_shares_len)) {
                break;
            }
            while (ex_iob->size() > 0) {
                key_share key_share;
                uint16_t key_share_len = 0;
                if (!read_i16_from_iob(ex_iob, key_share.group) ||
                    !read_i16_from_iob(ex_iob, key_share_len)) {
                    break;
                }
                key_share.data.resize(key_share_len);
                if (!read_string_from_iob(ex_iob, key_share.data)) {
                    break;
                }
                raw->key_shares.push_back(std::move(key_share));
            }
        } break;
        case TLS_EXTENSION_EARLY_DATA: {
            raw->is_support_early_data = true;
        } break;
        case TLS_EXTENSION_PSK_MODES: {
            uint8_t psk_modes_len = 0;
            if (!read_i8_from_iob(ex_iob, psk_modes_len)) {
                break;
            }
            for (uint8_t i = 0; i < psk_modes_len; i++) {
                uint8_t psk_mode = 0;
                if (!read_i8_from_iob(ex_iob, psk_mode)) {
                    break;
                }
                raw->psk_modes.push_back(psk_mode);
            }
        } break;
        case TLS_EXTENSION_PRE_SHARED_KEY: {
            uint16_t psk_identities_len = 0;
            if (!read_i16_from_iob(ex_iob, psk_identities_len)) {
                break;
            }
            while (psk_identities_len > 0) {
                uint16_t psk_identity_len = 0;
                if (!read_i16_from_iob(ex_iob, psk_identity_len)) {
                    break;
                }
                psk_identity psk_identity;
                psk_identity.identity.resize(psk_identity_len);
                if (!read_string_from_iob(ex_iob, psk_identity.identity) ||
                    !read_i32_from_iob(ex_iob, psk_identity.obfuscated_ticket_age)) {
                    break;
                }
                psk_identities_len -= (2 + psk_identity_len + 4);
            }
            if (psk_identities_len != 0) {
                break;
            }

            uint16_t psk_binders_len = 0;
            if (!read_i16_from_iob(ex_iob, psk_binders_len)) {
                break;
            }
            while (psk_binders_len > 0) {
                uint8_t psk_biner_len = 0;
                if (!read_i8_from_iob(ex_iob, psk_biner_len)) {
                    break;
                }
                std::string psk_binder(psk_biner_len, '\0');
                if (!read_string_from_iob(ex_iob, psk_binder)) {
                    break;
                }
                raw->psk_binders.push_back(std::move(psk_binder));
                psk_binders_len -= uint16_t(1 + psk_biner_len);
            }
        } break;
        default: {
            extension additional_extension;
            additional_extension.type = extension_type;
            additional_extension.data.resize(extension_len);
            if (!read_string_from_iob(ex_iob, additional_extension.data)) {
                break;
            }
            raw->additional_extensions.push_back(std::move(additional_extension));
        } break;
        }

        if (ex_iob->size() != 0) {
            break;
        }

        exs_iob->shift(extension_len);
    }

    bool ret = false;
    if (exs_iob->size() == 0) {
        iob->shift(extensions_len);
        ret = true;
    }
    ex_iob->unrefer();
    exs_iob->unrefer();

    return ret;
}

server_hello_message *new_server_hello_message() {
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

bool pack_server_hello_message(void *msg, io_buffer *iob) {
    auto raw = (const server_hello_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_SERVER_HELLO, iob)) {
        return false;
    }

    // Skip to pack payload length with 3 bytes.
    uint32_t payload_len_pos = iob->size();
    if (!iob->write(nullptr, 3)) {
        return false;
    }

    // Pack server tls version with 2 bytes.
    if (!write_i16_to_iob(raw->legacy_version, iob)) {
        return false;
    }

    // Pack random with 32 bytes.
    if (!iob->write((block_t *)raw->random, 32)) {
        return false;
    }

    // Pack session id.
    if (!write_i8_to_iob(raw->session_id.size(), iob)) {
        return false;
    }
    if (!raw->session_id.empty() && !write_string_to_iob(raw->session_id, iob)) {
        return false;
    }

    // Pack cipher suite.
    if (!write_i16_to_iob(raw->cipher_suite, iob)) {
        return false;
    }

    // Pack compression method.
    if (!write_i8_to_iob(raw->compression_method, iob)) {
        return false;
    }

    // Skip to pack extensions length with 2 bytes.
    uint32_t extension_len_pos = iob->size();
    if (!iob->write(nullptr, 2)) {
        return false;
    }

    if (raw->is_support_ocsp_stapling) {
        if (!write_i16_to_iob(TLS_EXTENSION_STATUS_REQUEST, iob) ||
            !write_i16_to_iob(0, iob)) {
            return false;
        }
    }

    if (raw->is_support_session_ticket) {
        if (!write_i16_to_iob(TLS_EXTENSION_SESSION_TICKET, iob) ||
            !write_i16_to_iob(0, iob)) {
            return false;
        }
    }

    if (raw->is_support_renegotiation_info) {
        if (!write_i16_to_iob(TLS_EXTENSION_RENEGOTIATION_INFO, iob) ||
            !write_i16_to_iob(1 + raw->renegotiation_info.size(), iob) ||
            !write_i8_to_iob(raw->renegotiation_info.size(), iob) ||
            !write_string_to_iob(raw->renegotiation_info, iob)) {
            return false;
        }
    }

    if (!raw->alpn.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_ALPN, iob) ||
            !write_i16_to_iob(2 + 1 + raw->alpn.size(), iob) ||
            !write_i16_to_iob(1 + raw->alpn.size(), iob) ||
            !write_i8_to_iob(raw->alpn.size(), iob) ||
            !write_string_to_iob(raw->alpn, iob)) {
            return false;
        }
    }

    if (!raw->scts.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_SCT, iob)) {
            return false;
        }
        uint32_t len_pos = iob->size();
        if (!iob->write(nullptr, 2 * 2)) {
            return false;
        }
        for (auto &sct : raw->scts) {
            if (!write_i16_to_iob(sct.size(), iob) || !write_string_to_iob(sct, iob)) {
                return false;
            }
        }
        uint16_t len = iob->size() - len_pos - 2;
        __pack_i16((block_t *)iob->data() + len_pos, len);
        __pack_i16((block_t *)iob->data() + len_pos + 2, len - 2);
    }

    if (raw->supported_version != 0) {
        if (!write_i16_to_iob(TLS_EXTENSION_SUPPORTED_VERSIONS, iob) ||
            !write_i16_to_iob(2, iob) || !write_i16_to_iob(raw->supported_version, iob)) {
            return false;
        }
    }

    if (raw->has_selected_key_share) {
        if (!write_i16_to_iob(TLS_EXTENSION_KEY_SHARE, iob) ||
            !write_i16_to_iob(2 + 2 + raw->selected_key_share.data.size(), iob) ||
            !write_i16_to_iob(raw->selected_key_share.group, iob) ||
            !write_i16_to_iob(raw->selected_key_share.data.size(), iob) ||
            !write_string_to_iob(raw->selected_key_share.data, iob)) {
            return false;
        }
    }

    if (raw->selected_group != 0) {
        if (!write_i16_to_iob(TLS_EXTENSION_KEY_SHARE, iob) ||
            !write_i16_to_iob(2, iob) || !write_i16_to_iob(raw->selected_group, iob)) {
            return false;
        }
    }

    if (raw->has_selected_psk_identity) {
        if (!write_i16_to_iob(TLS_EXTENSION_PRE_SHARED_KEY, iob) ||
            !write_i16_to_iob(2, iob) ||
            !write_i16_to_iob(raw->selected_psk_identity, iob)) {
            return false;
        }
    }

    if (!raw->cookie.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_COOKIE, iob) ||
            !write_i16_to_iob(2 + raw->cookie.size(), iob) ||
            !write_i16_to_iob(raw->cookie.size(), iob) ||
            !write_string_to_iob(raw->cookie, iob)) {
            return false;
        }
    }

    // Pack supported point formats extenion.
    if (!raw->supported_point_formats.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_SUPPORTED_POINTS, iob) ||
            !write_i16_to_iob(1 + raw->supported_point_formats.size() * 2, iob) ||
            !write_i8_to_iob(raw->supported_point_formats.size(), iob)) {
            return false;
        }
        for (auto point : raw->supported_point_formats) {
            if (!write_i8_to_iob(point, iob)) {
                return false;
            }
        }
    }

    // Pack extensions length.
    uint16_t extension_len = iob->size() - extension_len_pos - 2;
    __pack_i16((block_t *)iob->data() + extension_len_pos, extension_len);

    // Pack payload length.
    uint32_t payload_len = iob->size() - payload_len_pos - 3;
    __pack_i16((block_t *)iob->data() + payload_len_pos, payload_len);

    return true;
}

bool unpack_server_hello_message(io_buffer *iob, void *msg) {
    auto raw = (server_hello_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_SERVER_HELLO) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_len = 0;
    if (!read_i24_from_iob(iob, payload_len)) {
        return false;
    }

    // Unpack client tls version.
    if (!read_i16_from_iob(iob, raw->legacy_version)) {
        return false;
    }

    // Unpack random with 32 bytes.
    if (!iob->read((block_t *)raw->random, 32)) {
        return false;
    }

    // Unpack session id.
    uint8_t session_id_len = 0;
    if (!read_i8_from_iob(iob, session_id_len)) {
        return false;
    }
    if (session_id_len > 0) {
        raw->session_id.resize(session_id_len);
        if (!read_string_from_iob(iob, raw->session_id)) {
            return false;
        }
    }

    // Unpack cipher suite.
    if (!read_i16_from_iob(iob, raw->cipher_suite)) {
        return false;
    }

    // Unpack compression method.
    if (!read_i8_from_iob(iob, raw->compression_method)) {
        return false;
    }

    // Unpack extensions length.
    uint16_t extensions_len = 0;
    if (!read_i16_from_iob(iob, extensions_len)) {
        return false;
    } else if (iob->size() < extensions_len) {
        return false;
    }

    auto ex_iob = io_buffer::create();
    auto exs_iob = io_buffer::create_by_refence(iob->data(), extensions_len);
    while (exs_iob->size() > 0) {
        uint16_t extension_type = -1;
        uint16_t extension_len = 0;
        if (!read_i16_from_iob(exs_iob, extension_type) ||
            !read_i16_from_iob(exs_iob, extension_len)) {
            break;
        }

        if (exs_iob->size() < extension_len) {
            break;
        } else if (!ex_iob->reset_by_reference(exs_iob->data(), extension_len)) {
            break;
        }

        switch (extension_type) {
        case TLS_EXTENSION_STATUS_REQUEST: {
            raw->is_support_ocsp_stapling = true;
        } break;
        case TLS_EXTENSION_SESSION_TICKET: {
            raw->is_support_session_ticket = true;
        } break;
        case TLS_EXTENSION_RENEGOTIATION_INFO: {
            uint8_t len = 0;
            if (!read_i8_from_iob(ex_iob, len)) {
                break;
            }
            raw->renegotiation_info.resize(len);
            if (!read_string_from_iob(ex_iob, raw->renegotiation_info)) {
                break;
            }
            raw->is_support_renegotiation_info = true;
        } break;
        case TLS_EXTENSION_ALPN: {
            uint16_t alpns_len = 0;
            if (!read_i16_from_iob(ex_iob, alpns_len)) {
                break;
            }
            uint8_t alpn_len = 0;
            if (!read_i8_from_iob(ex_iob, alpn_len)) {
                break;
            }
            raw->alpn.resize(alpns_len);
            if (!read_string_from_iob(ex_iob, raw->alpn)) {
                break;
            }
        } break;
        case TLS_EXTENSION_SCT: {
            uint16_t scts_len = 0;
            if (!read_i16_from_iob(ex_iob, scts_len)) {
                break;
            }
            while (ex_iob->size() > 0) {
                uint16_t sct_len = 0;
                if (!read_i16_from_iob(ex_iob, sct_len)) {
                    break;
                }
                std::string sct(scts_len, '\0');
                if (!read_string_from_iob(ex_iob, sct)) {
                    break;
                }
                raw->scts.push_back(std::move(sct));
            }
        } break;
        case TLS_EXTENSION_SUPPORTED_VERSIONS: {
            read_i16_from_iob(ex_iob, raw->supported_version);
        } break;
        case TLS_EXTENSION_COOKIE: {
            uint16_t len = 0;
            if (!read_i16_from_iob(ex_iob, len)) {
                break;
            }
            raw->cookie.resize(len);
            if (!read_string_from_iob(ex_iob, raw->cookie)) {
                break;
            }
        } break;
        case TLS_EXTENSION_KEY_SHARE:
            if (ex_iob->size() == 2) {
                if (!read_i16_from_iob(ex_iob, raw->selected_group)) {
                    break;
                }
            } else {
                if (!read_i16_from_iob(ex_iob, raw->selected_key_share.group)) {
                    break;
                }
                uint16_t len = 0;
                if (!read_i16_from_iob(ex_iob, len)) {
                    break;
                }
                raw->selected_key_share.data.resize(len);
                if (!read_string_from_iob(ex_iob, raw->selected_key_share.data)) {
                    break;
                }
                raw->has_selected_key_share = true;
            }
            break;
        case TLS_EXTENSION_PRE_SHARED_KEY: {
            if (!read_i16_from_iob(ex_iob, raw->selected_psk_identity)) {
                break;
            }
            raw->has_selected_psk_identity = true;
        } break;
        case TLS_EXTENSION_SUPPORTED_POINTS: {
            uint8_t points_len = 0;
            if (!read_i8_from_iob(ex_iob, points_len)) {
                break;
            }
            while (ex_iob->size() > 0) {
                point_format_type point_type = 0;
                if (!read_i8_from_iob(ex_iob, point_type)) {
                    break;
                }
                raw->supported_point_formats.push_back(point_type);
            }
        } break;
        default:
            ex_iob->shift(extension_len);
            break;
        }

        if (ex_iob->size() != 0) {
            break;
        }

        exs_iob->shift(extension_len);
    }

    bool ret = false;
    if (exs_iob->size() == 0) {
        iob->shift(extensions_len);
        ret = true;
    }
    ex_iob->unrefer();
    exs_iob->unrefer();

    return ret;
}

new_session_ticket_message *new_new_session_ticket_message() {
    auto msg = object_create<new_session_ticket_message>();
    if (msg) {
        msg->lifetime_hint = 0;
    }
    return msg;
}

bool pack_new_session_ticket_message(void *msg, io_buffer *iob) {
    auto raw = (const new_session_ticket_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_NEW_SESSION_TICKET, iob)) {
        return false;
    }

    // Pack payload length.
    if (!write_i24_to_iob(4 + 2 + raw->ticket.size(), iob)) {
        return false;
    }

    // Pack lifetime hint.
    if (!write_i32_to_iob(raw->lifetime_hint, iob)) {
        return false;
    }

    // Pack ticket.
    if (!write_i16_to_iob(raw->ticket.size(), iob) ||
        !write_string_to_iob(raw->ticket, iob)) {
        return false;
    }

    return true;
}

bool unpack_new_session_ticket_message(io_buffer *iob, void *msg) {
    auto raw = (new_session_ticket_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_HELLO_REQUEST) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_len = 0;
    if (!read_i24_from_iob(iob, payload_len)) {
        return false;
    }

    // Unpack lifetime hint.
    if (!read_i32_from_iob(iob, raw->lifetime_hint)) {
        return false;
    }

    // Unpack ticket.
    uint16_t ticket_len = 0;
    if (!read_i16_from_iob(iob, ticket_len)) {
        return false;
    }
    raw->ticket.resize(ticket_len);
    if (!read_string_from_iob(iob, raw->ticket)) {
        return false;
    }

    return true;
}

new_session_ticket_tls13_message *new_new_session_ticket_tls13_message() {
    auto msg = object_create<new_session_ticket_tls13_message>();
    if (msg) {
        msg->lifetime = 0;
        msg->age_add = 0;
        msg->max_early_data_size = 0;
    }
    return msg;
}

bool pack_new_session_ticket_tls13_message(void *msg, io_buffer *iob) {
    auto raw = (const new_session_ticket_tls13_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_NEW_SESSION_TICKET, iob)) {
        return false;
    }

    // Skip to pack payload length with 3 bytes.
    uint32_t payload_len_pos = iob->size();
    if (!iob->write(nullptr, 3)) {
        return false;
    }

    // Pack ticket lifetime.
    if (!write_i32_to_iob(raw->lifetime, iob)) {
        return false;
    }

    // Pack ticket age add time.
    if (!write_i32_to_iob(raw->age_add, iob)) {
        return false;
    }

    // Pack ticket nonce.
    if (!write_i8_to_iob(raw->nonce.size(), iob)) {
        return false;
    }
    if (!raw->nonce.empty() && !write_string_to_iob(raw->nonce, iob)) {
        return false;
    }

    // Pack ticket lable.
    if (!write_i16_to_iob(raw->label.size(), iob)) {
        return false;
    }
    if (!raw->label.empty() && !write_string_to_iob(raw->label, iob)) {
        return false;
    }

    // Pack extensions.
    if (raw->max_early_data_size == 0) {
        if (!write_i16_to_iob(0, iob)) {
            return false;
        }
    } else {
        if (!write_i16_to_iob(8, iob) ||
            !write_i16_to_iob(TLS_EXTENSION_EARLY_DATA, iob) ||
            !write_i16_to_iob(2, iob) ||
            !write_i32_to_iob(raw->max_early_data_size, iob)) {
            return false;
        }
    }

    // Pack payload length.
    uint32_t payload_len = iob->size() - payload_len_pos - 3;
    __pack_i24((block_t *)iob->data() + payload_len_pos, payload_len);

    return true;
}

bool unpack_new_session_ticket_tls13_message(io_buffer *iob, void *msg) {
    auto raw = (new_session_ticket_tls13_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_NEW_SESSION_TICKET) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_len = 0;
    if (!read_i24_from_iob(iob, payload_len)) {
        return false;
    }

    // Unpack ticket lifetime.
    if (!read_i32_from_iob(iob, raw->lifetime)) {
        return false;
    }

    // Unpack ticket age add time.
    if (!read_i32_from_iob(iob, raw->age_add)) {
        return false;
    }

    // Unpack ticket nonce.
    uint8_t nonce_len = 0;
    if (!read_i8_from_iob(iob, nonce_len)) {
        return false;
    }
    if (nonce_len > 0) {
        raw->nonce.resize(nonce_len);
        if (!read_string_from_iob(iob, raw->nonce)) {
            return false;
        }
    }

    // Unpack ticket lable.
    uint8_t lable_len = 0;
    if (!read_i8_from_iob(iob, lable_len)) {
        return false;
    }
    if (lable_len > 0) {
        raw->label.resize(nonce_len);
        if (!read_string_from_iob(iob, raw->label)) {
            return false;
        }
    }

    // Unpack extensions.
    uint16_t extensions_len = 0;
    if (!read_i16_from_iob(iob, extensions_len)) {
        return false;
    }
    if (extensions_len > 0) {
        uint16_t extension_type = 0;
        uint16_t extension_len = 0;
        if (!read_i16_from_iob(iob, extension_type) ||
            !read_i16_from_iob(iob, extension_len) ||
            !read_i32_from_iob(iob, raw->max_early_data_size)) {
            return false;
        }
    }

    return true;
}

end_early_data_message *new_end_early_data_message() {
    return object_create<end_early_data_message>();
}

bool pack_end_early_data_message(void *msg, io_buffer *iob) {
    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_END_OF_EARLY_DATA, iob)) {
        return false;
    }

    // Pack payload length.
    if (!write_i24_to_iob(0, iob)) {
        return false;
    }

    return true;
}

bool unpack_end_early_data_message(io_buffer *iob, void *msg) {
    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_END_OF_EARLY_DATA) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_len = 0;
    if (!read_i24_from_iob(iob, payload_len)) {
        return false;
    }

    return true;
}

encrypted_extensions_message *new_encrypted_extensions_message() {
    auto msg = object_create<encrypted_extensions_message>();
    if (msg) {
        msg->is_support_early_data = false;
    }
    return msg;
}

bool pack_encrypted_extensions_message(void *msg, io_buffer *iob) {
    auto raw = (const encrypted_extensions_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_ENCRYPTED_EXTENSIONS, iob)) {
        return false;
    }

    // Skip to pack payload length with 3 bytes.
    uint32_t payload_len_pos = iob->size();
    if (!iob->write(nullptr, 3)) {
        return false;
    }

    // Skip to pack extensions length with 2 bytes.
    uint32_t extension_len_pos = iob->size();
    if (!iob->write(nullptr, 2)) {
        return false;
    }

    if (!raw->alpn.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_ALPN, iob) ||
            !write_i16_to_iob(2 + 1 + raw->alpn.size(), iob) ||
            !write_i16_to_iob(1 + raw->alpn.size(), iob) ||
            !write_i8_to_iob(raw->alpn.size(), iob) ||
            !write_string_to_iob(raw->alpn, iob)) {
            return false;
        }
    }

    if (raw->is_support_early_data) {
        if (!write_i16_to_iob(TLS_EXTENSION_EARLY_DATA, iob) ||
            !write_i16_to_iob(0, iob)) {
            return false;
        }
    }

    for (auto &ext : raw->additional_extensions) {
        if (!write_i16_to_iob(ext.type, iob) || !write_i16_to_iob(ext.data.size(), iob) ||
            !write_string_to_iob(ext.data, iob)) {
            return false;
        }
    }

    // Pack extensions length.
    uint16_t extension_len = iob->size() - extension_len_pos - 2;
    __pack_i16((block_t *)iob->data() + extension_len_pos, extension_len);

    // Pack payload length.
    uint32_t payload_len = iob->size() - payload_len_pos - 3;
    __pack_i24((block_t *)iob->data() + payload_len_pos, payload_len);

    return true;
}

bool unpack_encrypted_extensions_message(io_buffer *iob, void *msg) {
    auto raw = (encrypted_extensions_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_ENCRYPTED_EXTENSIONS) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_len = 0;
    if (!read_i24_from_iob(iob, payload_len)) {
        return false;
    }

    // Unpack extensions length.
    uint16_t extensions_len = 0;
    if (!read_i16_from_iob(iob, extensions_len)) {
        return false;
    } else if (iob->size() < extensions_len) {
        return false;
    }

    auto ex_iob = io_buffer::create();
    auto exs_iob = io_buffer::create_by_refence(iob->data(), extensions_len);
    while (exs_iob->size() > 0) {
        uint16_t extension_type = -1;
        uint16_t extension_len = 0;
        if (!read_i16_from_iob(exs_iob, extension_type) ||
            !read_i16_from_iob(exs_iob, extension_len)) {
            break;
        }

        if (exs_iob->size() < extension_len) {
            break;
        } else if (!ex_iob->reset_by_reference(exs_iob->data(), extension_len)) {
            break;
        }

        switch (extension_type) {
        case TLS_EXTENSION_ALPN: {
            uint16_t alpns_len = 0;
            if (!read_i16_from_iob(ex_iob, alpns_len)) {
                return false;
            }
            uint8_t alpn_len = 0;
            if (!read_i8_from_iob(ex_iob, alpn_len)) {
                return false;
            }
            raw->alpn.resize(alpn_len);
            if (!read_string_from_iob(ex_iob, raw->alpn)) {
                return false;
            }
        } break;
        case TLS_EXTENSION_EARLY_DATA: {
            raw->is_support_early_data = true;
        } break;
        default: {
            extension additional_extension;
            additional_extension.type = extension_type;
            additional_extension.data.resize(extension_len);
            if (!read_string_from_iob(ex_iob, additional_extension.data)) {
                return false;
            }
            raw->additional_extensions.push_back(std::move(additional_extension));
        } break;
        }

        if (ex_iob->size() != 0) {
            break;
        }

        exs_iob->shift(extension_len);
    }

    bool ret = false;
    if (exs_iob->size() == 0) {
        iob->shift(extensions_len);
        ret = true;
    }
    exs_iob->unrefer();
    ex_iob->unrefer();

    return ret;
}

certificate_message *new_certificate_message() {
    return object_create<certificate_message>();
}

bool pack_certificate_message(void *msg, io_buffer *iob) {
    auto raw = (const certificate_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_CERTIFICATE, iob)) {
        return false;
    }

    // Skip to pack payload length with 3 bytes.
    uint32_t payload_len_pos = iob->size();
    if (!iob->write(nullptr, 3)) {
        return false;
    }

    // Skip to pack certificates length with 3 bytes.
    uint32_t certificates_len_pos = iob->size();
    if (!iob->write(nullptr, 3)) {
        return false;
    }

    // Pack certificates.
    for (auto &cert : raw->certificates) {
        // Pack certificate.
        if (!write_i24_to_iob(cert.size(), iob) || !write_string_to_iob(cert, iob)) {
            return false;
        }
    }

    // Pack certificates length.
    uint32_t certificates_len = iob->size() - certificates_len_pos - 3;
    __pack_i24((block_t *)iob->data() + certificates_len_pos, certificates_len);

    // Pack payload length.
    uint32_t payload_len = iob->size() - payload_len_pos - 3;
    __pack_i24((block_t *)iob->data() + payload_len_pos, payload_len);

    return true;
}

bool unpack_certificate_message(io_buffer *iob, void *msg) {
    auto raw = (certificate_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_CERTIFICATE) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_len = 0;
    if (!read_i24_from_iob(iob, payload_len)) {
        return false;
    }

    // Unpack certificates length.
    uint32_t certs_len = 0;
    if (!read_i24_from_iob(iob, certs_len)) {
        return false;
    } else if (iob->size() < certs_len) {
        return false;
    }

    auto cert_iob = io_buffer::create_by_refence(iob->data(), certs_len);
    while (cert_iob->size() > 0) {
        uint32_t cert_len = 0;
        if (!read_i24_from_iob(cert_iob, cert_len)) {
            break;
        }
        std::string cert(cert_len, '\0');
        if (!read_string_from_iob(cert_iob, cert)) {
            break;
        }
        raw->certificates.push_back(std::move(cert));
    }

    bool ret = false;
    if (cert_iob->size() == 0) {
        iob->shift(certs_len);
        ret = true;
    }
    cert_iob->unrefer();

    return ret;
}

certificate_tls13_message *new_certificate_tls13_message() {
    auto msg = object_create<certificate_tls13_message>();
    if (msg) {
        msg->is_support_ocsp_stapling = false;
        msg->is_support_scts = false;
    }
    return msg;
}

bool pack_certificate_tls13_message(void *msg, io_buffer *iob) {
    auto raw = (const certificate_tls13_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_CERTIFICATE, iob)) {
        return false;
    }

    // Skip to pack payload length with 3 bytes.
    uint32_t payload_len_pos = iob->size();
    if (!iob->write(nullptr, 3)) {
        return false;
    }

    // Pack certificate request context length.
    if (!write_i8_to_iob(0, iob)) {
        return false;
    }

    // Skip to pack certificates length with 3 bytes.
    uint32_t certificates_len_pos = iob->size();
    if (!iob->write(nullptr, 3)) {
        return false;
    }

    // Pack certificates.
    for (int32_t i = 0; i < (int32_t)raw->certificates.size(); i++) {
        if (i > 0) {
            break;
        }

        // Pack certificate.
        if (!write_i24_to_iob(raw->certificates[i].size(), iob) ||
            !write_string_to_iob(raw->certificates[i], iob)) {
            return false;
        }

        // Skip to pack extensions length.
        uint32_t extensions_len_pos = iob->size();
        if (!iob->write(nullptr, 2)) {
            return false;
        }

        // Pack status request extension.
        if (raw->is_support_ocsp_stapling) {
            if (!write_i16_to_iob(TLS_EXTENSION_STATUS_REQUEST, iob) ||
                !write_i16_to_iob(4 + raw->ocsp_staple.size(), iob) ||
                !write_i8_to_iob(TLS_OCSP_STATUS, iob) ||
                !write_i24_to_iob(raw->ocsp_staple.size(), iob) ||
                !write_string_to_iob(raw->ocsp_staple, iob)) {
                return false;
            }
        }

        // Pack sct extension.
        if (raw->is_support_scts) {
            if (!write_i16_to_iob(TLS_EXTENSION_SCT, iob)) {
                return false;
            }
            uint32_t len_pos = iob->size();
            if (!iob->write(nullptr, 2 * 2)) {
                return false;
            }
            for (int32_t ii = 0; ii < (int32_t)raw->scts.size(); ii++) {
                if (!write_i16_to_iob(raw->scts[i].size(), iob) ||
                    !write_string_to_iob(raw->scts[i], iob)) {
                    return false;
                }
            }
            uint16_t len = iob->size() - len_pos - 2;
            __pack_i16((block_t *)iob->data() + len_pos, len);
            __pack_i16((block_t *)iob->data() + len_pos + 2, len - 2);
        }

        // Pack extensions length.
        uint16_t extensions_len = iob->size() - extensions_len_pos - 2;
        __pack_i16((block_t *)iob->data() + extensions_len_pos, extensions_len);
    }

    // Pack certificates length.
    uint32_t certificates_len = iob->size() - certificates_len_pos - 3;
    __pack_i24((block_t *)iob->data() + certificates_len_pos, certificates_len);

    // Pack payload length.
    uint32_t payload_len = iob->size() - payload_len_pos - 3;
    __pack_i24((block_t *)iob->data() + payload_len_pos, payload_len);

    return true;
}

bool unpack_certificate_tls13_message(io_buffer *iob, void *msg) {
    auto raw = (certificate_tls13_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_CERTIFICATE) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_len = 0;
    if (!read_i24_from_iob(iob, payload_len)) {
        return false;
    }

    // Unpack certificate request context length.
    uint8_t context_len = 0;
    if (!read_i8_from_iob(iob, context_len)) {
        return false;
    }

    // Unpack certificates length.
    uint32_t certs_len = 0;
    if (!read_i24_from_iob(iob, certs_len)) {
        return false;
    } else if (iob->size() < certs_len) {
        return false;
    }

    // Unpack certificates.
    auto cert_iob = io_buffer::create_by_refence(iob->data(), certs_len);
    while (cert_iob->size() > 0) {
        uint32_t cert_len = 0;
        if (!read_i24_from_iob(cert_iob, cert_len)) {
            break;
        }
        std::string cert(cert_len, '\0');
        if (!read_string_from_iob(cert_iob, cert)) {
            break;
        }

        uint16_t extensions_len = 0;
        if (!read_i16_from_iob(cert_iob, extensions_len)) {
            break;
        }

        if (raw->certificates.size() > 0) {
            if (cert_iob->shift(extensions_len) < 0) {
                break;
            }
            continue;
        }

        while (extensions_len > 0) {
            uint16_t extension_type = -1;
            uint16_t extension_len = 0;
            if (!read_i16_from_iob(cert_iob, extension_type) ||
                !read_i16_from_iob(cert_iob, extension_len)) {
                break;
            }
            if (extension_type == TLS_EXTENSION_STATUS_REQUEST) {
                uint8_t status = 0;
                if (!read_i8_from_iob(cert_iob, status)) {
                    break;
                }
                uint32_t ocsp_staple_len = 0;
                if (!read_i24_from_iob(cert_iob, ocsp_staple_len)) {
                    break;
                } else if (ocsp_staple_len > 0) {
                    raw->ocsp_staple.resize(ocsp_staple_len);
                    if (!read_string_from_iob(cert_iob, raw->ocsp_staple)) {
                        break;
                    }
                }
                raw->is_support_ocsp_stapling = true;
            } else if (extension_type == TLS_EXTENSION_SCT) {
                uint16_t scts_len = 0;
                if (!read_i16_from_iob(cert_iob, scts_len)) {
                    break;
                }
                while (scts_len > 0) {
                    uint16_t sct_len = 0;
                    if (!read_i16_from_iob(cert_iob, sct_len)) {
                        break;
                    } else if (sct_len > 0) {
                        std::string sct(sct_len, '\0');
                        if (!read_string_from_iob(cert_iob, sct)) {
                            break;
                        }
                        raw->scts.push_back(std::move(sct));
                        scts_len -= (2 + sct_len);
                    }
                }
                if (scts_len > 0) {
                    break;
                }
                raw->is_support_scts = true;
            } else {
                if (cert_iob->shift(extension_len) < 0) {
                    break;
                }
            }
            extensions_len -= extension_len;
        }

        if (extensions_len > 0) {
            break;
        }

        raw->certificates.push_back(std::move(cert));
    }

    bool ret = false;
    if (cert_iob->size() == 0) {
        iob->shift(certs_len);
        ret = true;
    }
    cert_iob->unrefer();

    return ret;
}

server_key_exchange_message *new_server_key_exchange_message() {
    return object_create<server_key_exchange_message>();
}

bool pack_server_key_exchange_message(void *msg, io_buffer *iob) {
    auto raw = (const server_key_exchange_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_SERVER_KEY_EXCHANGE, iob)) {
        return false;
    }

    // Pack payload length.
    if (!write_i24_to_iob(raw->key.size(), iob)) {
        return false;
    }

    // Pack key.
    if (!write_string_to_iob(raw->key, iob)) {
        return false;
    }

    return true;
}

bool unpack_server_key_exchange_message(io_buffer *iob, void *msg) {
    auto raw = (server_key_exchange_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_SERVER_KEY_EXCHANGE) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_len = 0;
    if (!read_i24_from_iob(iob, payload_len)) {
        return false;
    }

    // Unpack key.
    raw->key.resize(payload_len);
    if (!read_string_from_iob(iob, raw->key)) {
        return false;
    }

    return true;
}

certificate_req_message *new_certificate_req_message() {
    auto msg = object_create<certificate_req_message>();
    if (msg) {
        msg->has_signature_algorithms = false;
    }
    return msg;
}

bool pack_certificate_req_message(void *msg, io_buffer *iob) {
    auto raw = (const certificate_req_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_CERTIFICATE_REQUEST, iob)) {
        return false;
    }

    // Skip to pack payload length with 3 bytes.
    uint32_t payload_len_pos = iob->size();
    if (!iob->write(nullptr, 3)) {
        return false;
    }

    // Pack certificate types.
    if (!write_i8_to_iob(raw->certificate_types.size(), iob)) {
        return false;
    }
    for (auto cert_type : raw->certificate_types) {
        if (!write_i8_to_iob(cert_type, iob)) {
            return false;
        }
    }

    // Pack signature algorithms.
    if (raw->has_signature_algorithms) {
        if (!write_i16_to_iob(raw->supported_signature_algorithms.size() * 2, iob)) {
            return false;
        }
        for (auto algo : raw->supported_signature_algorithms) {
            if (!write_i16_to_iob(algo, iob)) {
                return false;
            }
        }
    }

    // Pack certificate authorities.
    int32_t certificate_authorities_len_pos = iob->size();
    if (!iob->write(nullptr, 2)) {
        return false;
    }
    for (auto &auth : raw->certificate_authorities) {
        if (!write_i16_to_iob(auth.size(), iob) || !write_string_to_iob(auth, iob)) {
            return false;
        }
    }
    uint16_t certificate_authorities_len =
        iob->size() - certificate_authorities_len_pos - 2;
    __pack_i16((block_t *)iob->data() + certificate_authorities_len_pos,
               certificate_authorities_len);

    // Pack payload length.
    uint32_t payload_len = iob->size() - payload_len_pos - 3;
    __pack_i24((block_t *)iob->data() + payload_len_pos, payload_len);

    return true;
}

bool unpack_certificate_req_message(io_buffer *iob, void *msg) {
    auto raw = (certificate_req_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_CERTIFICATE_REQUEST) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_size = 0;
    if (!read_i24_from_iob(iob, payload_size)) {
        return false;
    }

    // Unpack certificate types.
    uint16_t certificate_types_len = 0;
    if (!read_i16_from_iob(iob, certificate_types_len)) {
        return false;
    }
    for (int32_t i = 0; i < certificate_types_len; i++) {
        uint8_t certificate_type = 0;
        if (!read_i8_from_iob(iob, certificate_type)) {
            return false;
        }
        raw->certificate_types.push_back(certificate_type);
    }

    if (raw->has_signature_algorithms) {
        uint16_t signature_algorithms_len = 0;
        if (!read_i16_from_iob(iob, signature_algorithms_len)) {
            return false;
        }
        for (uint16_t i = 0; i < signature_algorithms_len; i += 2) {
            uint16_t signature_algorithms = 0;
            if (!read_i16_from_iob(iob, signature_algorithms)) {
                return false;
            }
            raw->supported_signature_algorithms.push_back(signature_algorithms);
        }
    }

    // Unpack certificate authorities.
    uint16_t certificate_authorities_len = 0;
    if (!read_i16_from_iob(iob, certificate_authorities_len)) {
        return false;
    }
    while (certificate_authorities_len > 0) {
        uint16_t cert_auth_len = 0;
        if (!read_i16_from_iob(iob, cert_auth_len)) {
            return false;
        }
        std::string cert_auth(cert_auth_len, '\0');
        if (!read_string_from_iob(iob, cert_auth)) {
            return false;
        }
        raw->certificate_authorities.push_back(std::move(cert_auth));
        certificate_authorities_len -= (2 + cert_auth_len);
    }

    return true;
}

certificate_req_tls13_message *new_certificate_req_tls13_message() {
    auto msg = object_create<certificate_req_tls13_message>();
    if (msg) {
        msg->is_support_ocsp_stapling = false;
        msg->is_support_scts = false;
    }
    return msg;
}

bool pack_certificate_req_tls13_message(void *msg, io_buffer *iob) {
    auto raw = (const certificate_req_tls13_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_CERTIFICATE_REQUEST, iob)) {
        return false;
    }

    // Skip to pack payload length with 3 bytes.
    uint32_t payload_len_pos = iob->size();
    if (!iob->write(nullptr, 3)) {
        return false;
    }

    // Pack certificate request context length.
    // SHALL be zero length unless used for post-handshake authentication.
    if (!write_i8_to_iob(0, iob)) {
        return false;
    }

    // Skip to pack extensions length with 2 bytes.
    uint32_t extension_len_pos = iob->size();
    if (!iob->write(nullptr, 2)) {
        return false;
    }

    // Pack status request extension.
    if (raw->is_support_ocsp_stapling) {
        if (!write_i16_to_iob(TLS_EXTENSION_STATUS_REQUEST, iob) ||
            !write_i16_to_iob(0, iob)) {
            return false;
        }
    }

    // Pack sct extension.
    if (raw->is_support_scts) {
        if (!write_i16_to_iob(TLS_EXTENSION_SCT, iob) || !write_i16_to_iob(0, iob)) {
            return false;
        }
    }

    // Pack signature algorithms extension.
    if (!raw->supported_signature_schemes.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_SIGNATURE_ALGORITHMS, iob) ||
            !write_i16_to_iob(2 + raw->supported_signature_schemes.size() * 2, iob) ||
            !write_i16_to_iob(raw->supported_signature_schemes.size() * 2, iob)) {
            return false;
        }
        for (auto scheme : raw->supported_signature_schemes) {
            if (!write_i16_to_iob(scheme, iob)) {
                return false;
            }
        }
    }

    // Pack signature algorithms certs extension.
    if (!raw->supported_signature_algorithms_certs.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT, iob) ||
            !write_i16_to_iob(2 + raw->supported_signature_algorithms_certs.size() * 2,
                              iob) ||
            !write_i16_to_iob(raw->supported_signature_algorithms_certs.size() * 2,
                              iob)) {
            return false;
        }
        for (auto algo : raw->supported_signature_algorithms_certs) {
            if (!write_i16_to_iob(algo, iob)) {
                return false;
            }
        }
    }

    // Pack signature algorithms certs extension.
    if (!raw->certificate_authorities.empty()) {
        if (!write_i16_to_iob(TLS_EXTENSION_CERTIFICATE_AUTHORITIES, iob)) {
            return false;
        }

        uint32_t len_pos = iob->size();
        if (!iob->write(nullptr, 4)) {
            return false;
        }
        for (auto &cert_auth : raw->certificate_authorities) {
            if (!write_i16_to_iob(cert_auth.size(), iob) ||
                !write_string_to_iob(cert_auth, iob)) {
                return false;
            }
        }
        uint16_t len = iob->size() - len_pos - 2;
        __pack_i16((block_t *)iob->data() + len_pos, len);
        __pack_i16((block_t *)iob->data() + len_pos + 2, len - 2);
    }

    // Pack extensions length.
    uint16_t extension_len = iob->size() - extension_len_pos - 2;
    __pack_i16((block_t *)iob->data() + extension_len_pos, extension_len);

    // Pack payload length.
    uint32_t payload_len = iob->size() - payload_len_pos - 3;
    __pack_i24((block_t *)iob->data() + payload_len_pos, payload_len);

    return true;
}

bool unpack_certificate_req_tls13_message(io_buffer *iob, void *msg) {
    auto raw = (certificate_req_tls13_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_CERTIFICATE_REQUEST) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_len = 0;
    if (!read_i24_from_iob(iob, payload_len)) {
        return false;
    }

    // Unpack certificate request context length.
    // SHALL be zero length unless used for post-handshake authentication.
    uint8_t context_len = 0;
    if (!read_i8_from_iob(iob, context_len)) {
        return false;
    }

    // Unpack extensions length.
    uint16_t extensions_len = 0;
    if (!read_i16_from_iob(iob, extensions_len)) {
        return false;
    } else if (iob->size() < extensions_len) {
        return false;
    }

    auto ex_iob = io_buffer::create();
    auto exs_iob = io_buffer::create_by_refence(iob->data(), extensions_len);
    while (exs_iob->size() > 0) {
        uint16_t extension_type = -1;
        uint16_t extension_len = 0;
        if (!read_i16_from_iob(exs_iob, extension_type) ||
            !read_i16_from_iob(exs_iob, extension_len)) {
            break;
        }

        if (exs_iob->size() < extension_len) {
            break;
        } else if (!ex_iob->reset_by_reference(exs_iob->data(), extension_len)) {
            break;
        }

        switch (extension_type) {
        case TLS_EXTENSION_STATUS_REQUEST: {
            raw->is_support_ocsp_stapling = true;
        } break;
        case TLS_EXTENSION_SCT: {
            raw->is_support_scts = true;
        } break;
        case TLS_EXTENSION_SIGNATURE_ALGORITHMS: {
            uint16_t schemes_len = 0;
            if (!read_i16_from_iob(ex_iob, schemes_len)) {
                break;
            }
            for (uint16_t i = 0; i < schemes_len; i += 2) {
                ssl::signature_scheme scheme = ssl::TLS_SIGN_SCHE_UNKNOWN;
                if (!read_i16_from_iob(ex_iob, scheme)) {
                    break;
                }
                raw->supported_signature_schemes.push_back(scheme);
            }
        } break;
        case TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT: {
            uint16_t algo_certs_len = 0;
            if (!read_i16_from_iob(ex_iob, algo_certs_len)) {
                break;
            }
            for (uint16_t i = 0; i < algo_certs_len; i += 2) {
                ssl::signature_scheme algo_cert = ssl::TLS_SIGN_SCHE_UNKNOWN;
                if (!read_i16_from_iob(ex_iob, algo_cert)) {
                    break;
                }
                raw->supported_signature_algorithms_certs.push_back(algo_cert);
            }
        } break;
        case TLS_EXTENSION_CERTIFICATE_AUTHORITIES: {
            uint16_t cert_auths_len = 0;
            if (!read_i16_from_iob(ex_iob, cert_auths_len)) {
                break;
            }
            while (cert_auths_len > 0) {
                uint8_t cert_auth_len = 0;
                if (!read_i8_from_iob(ex_iob, cert_auth_len)) {
                    break;
                }
                std::string cert_auth(cert_auth_len, '\0');
                if (!read_string_from_iob(ex_iob, cert_auth)) {
                    break;
                }
                raw->certificate_authorities.push_back(std::move(cert_auth));
                cert_auths_len -= uint16_t(2 + cert_auth_len);
            }
        } break;
        default:
            ex_iob->shift(extension_len);
            break;
        }

        if (ex_iob->size() != 0) {
            break;
        }

        exs_iob->shift(extension_len);
    }

    bool ret = false;
    if (exs_iob->size() == 0) {
        iob->shift(extensions_len);
        ret = true;
    }
    exs_iob->unrefer();
    ex_iob->unrefer();

    return ret;
}

server_hello_done_message *new_server_hello_done_message() {
    return object_create<server_hello_done_message>();
}

bool pack_server_hello_done_message(void *msg, io_buffer *iob) {
    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_SERVER_HELLO_DONE, iob)) {
        return false;
    }

    // Pack payload length.
    if (!write_i24_to_iob(0, iob)) {
        return false;
    }

    return true;
}

bool unpack_server_hello_done_message(io_buffer *iob, void *msg) {
    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_SERVER_HELLO_DONE) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_len = 0;
    if (!read_i24_from_iob(iob, payload_len)) {
        return false;
    }

    return true;
}

certificate_verify_message *new_certificate_verify_message() {
    auto msg = object_create<certificate_verify_message>();
    if (msg) {
        msg->has_signature_scheme = true;
    }
    return msg;
}

bool pack_certificate_verify_message(void *msg, io_buffer *iob) {
    auto raw = (const certificate_verify_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_CERTIFICATE_VERIFY, iob)) {
        return false;
    }

    // Pack payload length.
    uint32_t payload_len = 2 + raw->signature.size();
    if (raw->has_signature_scheme) {
        payload_len = 2 + 2 + raw->signature.size();
    }
    if (!write_i24_to_iob(payload_len, iob)) {
        return false;
    }

    if (raw->has_signature_scheme) {
        if (!write_i16_to_iob(raw->signature_scheme, iob)) {
            return false;
        }
    }

    // Pack signature data.
    if (!write_i16_to_iob(raw->signature.size(), iob) ||
        !write_string_to_iob(raw->signature, iob)) {
        return false;
    }

    return true;
}

bool unpack_certificate_verify_message(io_buffer *iob, void *msg) {
    auto raw = (certificate_verify_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_CERTIFICATE_VERIFY) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_size = 0;
    if (!read_i24_from_iob(iob, payload_size)) {
        return false;
    }

    if (raw->has_signature_scheme) {
        if (!read_i16_from_iob(iob, raw->signature_scheme)) {
            return false;
        }
    }

    uint16_t signature_len = 0;
    if (!read_i16_from_iob(iob, signature_len)) {
        return false;
    }
    raw->signature.resize(signature_len);
    if (!read_string_from_iob(iob, raw->signature)) {
        return false;
    }

    return true;
}

client_key_exchange_message *new_client_key_exchange_message() {
    return object_create<client_key_exchange_message>();
}

bool pack_client_key_exchange_message(void *msg, io_buffer *iob) {
    auto raw = (const client_key_exchange_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_CLIENT_KEY_EXCHANGE, iob)) {
        return false;
    }

    // Pack payload length.
    if (!write_i24_to_iob(raw->ciphertext.size(), iob)) {
        return false;
    }

    // Pack ciphertext.
    if (!write_string_to_iob(raw->ciphertext, iob)) {
        return false;
    }

    return true;
}

bool unpack_client_key_exchange_message(io_buffer *iob, void *msg) {
    auto raw = (client_key_exchange_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_CLIENT_KEY_EXCHANGE) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_size = 0;
    if (!read_i24_from_iob(iob, payload_size)) {
        return false;
    }

    // Unpack ciphertext.
    raw->ciphertext.resize(payload_size);
    if (!read_string_from_iob(iob, raw->ciphertext)) {
        return false;
    }

    return true;
}

finished_message *new_finished_message() {
    return object_create<finished_message>();
}

bool pack_finished_message(void *msg, io_buffer *iob) {
    auto raw = (const finished_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_FINISHED, iob)) {
        return false;
    }

    // Pack payload length.
    if (!write_i24_to_iob(raw->verify_data.size(), iob)) {
        return false;
    }

    // Pack verify data.
    if (!write_string_to_iob(raw->verify_data, iob)) {
        return false;
    }

    return true;
}

bool unpack_finished_message(io_buffer *iob, void *msg) {
    auto raw = (finished_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_FINISHED) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_len = 0;
    if (!read_i24_from_iob(iob, payload_len)) {
        return false;
    }

    // Unpack verify data.
    raw->verify_data.resize(payload_len);
    if (!read_string_from_iob(iob, raw->verify_data)) {
        return false;
    }

    return true;
}

certificate_status_message *new_certificate_status_message() {
    return object_create<certificate_status_message>();
}

bool pack_certificate_status_message(void *msg, io_buffer *iob) {
    auto raw = (const certificate_status_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_CERTIFICATE_STATUS, iob)) {
        return false;
    }

    // Pack payload length.
    if (!write_i24_to_iob(1 + 3 + raw->response.size(), iob)) {
        return false;
    }

    // Pack status.
    if (!write_i8_to_iob(TLS_OCSP_STATUS, iob) ||
        !write_i24_to_iob(raw->response.size(), iob) ||
        !write_string_to_iob(raw->response, iob)) {
        return false;
    }

    return true;
}

bool unpack_certificate_status_message(io_buffer *iob, void *msg) {
    auto raw = (certificate_status_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_CERTIFICATE_STATUS) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_size = 0;
    if (!read_i24_from_iob(iob, payload_size)) {
        return false;
    }

    // Unpack status.
    certicate_status_type status_type;
    if (!read_i8_from_iob(iob, status_type)) {
        return false;
    }
    uint32_t status_len = 0;
    if (!read_i24_from_iob(iob, status_len)) {
        return false;
    }
    raw->response.resize(status_len);
    if (!read_string_from_iob(iob, raw->response)) {
        return false;
    }

    return true;
}

key_update_message *new_key_update_message() {
    auto msg = object_create<key_update_message>();
    if (msg) {
        msg->update_requested = false;
    }
    return msg;
}

bool pack_key_update_message(void *msg, io_buffer *iob) {
    auto raw = (const key_update_message *)msg;

    // Pack message type with 1 bytes.
    if (!write_i8_to_iob(TLS_MSG_KEY_UPDATE, iob)) {
        return false;
    }

    // Pack payload length.
    if (!write_i24_to_iob(1, iob)) {
        return false;
    }

    if (!write_i8_to_iob(raw->update_requested ? 1 : 0, iob)) {
        return false;
    }

    return true;
}

bool unpack_key_update_message(io_buffer *iob, void *msg) {
    auto raw = (key_update_message *)msg;

    message_type tp;
    if (!read_i8_from_iob(iob, tp)) {
        return false;
    } else if (tp != TLS_MSG_KEY_UPDATE) {
        return false;
    }

    // Unpack payload length.
    uint32_t payload_len = 0;
    if (!read_i24_from_iob(iob, payload_len)) {
        return false;
    }

    uint8_t update_requested = 0;
    if (!read_i8_from_iob(iob, update_requested)) {
        return false;
    }
    raw->update_requested = (update_requested == 1);

    return true;
}

io_buffer *pack_msg_hash_message(const std::string &hash) {
    auto iob = io_buffer::create(4 + hash.size());
    write_i8_to_iob(TLS_MSG_MESSAGE_HASH, iob);
    write_i16_to_iob(0, iob);
    write_i8_to_iob(hash.size(), iob);
    write_string_to_iob(hash, iob);
    return iob;
}

}  // namespace tls
}  // namespace quic
}  // namespace proto
}  // namespace pump