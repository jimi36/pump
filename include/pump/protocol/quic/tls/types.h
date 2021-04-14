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
 
#ifndef pump_protocol_quic_tls_types_h
#define pump_protocol_quic_tls_types_h

#include <string>
#include <vector>

#include "pump/ssl/cert.h"
#include "pump/ssl/hash.h"
#include "pump/ssl/ecdhe.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    // TLS verison.
    typedef uint16_t version_type;
    const version_type TLS_VERSION_UNKNOWN = 0x0000;
    const version_type TLS_VERSION_10      = 0x0301;
    const version_type TLS_VSERVER_11      = 0x0302;
    const version_type TLS_VSERVER_12      = 0x0303;
    const version_type TLS_VSERVER_13      = 0x0304;

    // TLS handshake message types.
    typedef uint8_t message_type;
    const message_type TLS_MSG_HELLO_REQUEST        = 0;
    const message_type TLS_MSG_CLIENT_HELLO         = 1;
    const message_type TLS_MSG_SERVER_HELLO         = 2;
    const message_type TLS_MSG_NEW_SESSION_TICKET   = 4;
    const message_type TLS_MSG_END_OF_EARLY_DATA    = 5;
    const message_type TLS_MSG_ENCRYPTED_EXTENSIONS = 8;
    const message_type TLS_MSG_CERTIFICATE          = 11;
    const message_type TLS_MSG_SERVER_KEY_EXCHANGE  = 12;
    const message_type TLS_MSG_CERTIFICATE_REQUEST  = 13;
    const message_type TLS_MSG_SERVER_HELLO_DONE    = 14;
    const message_type TLS_MSG_CERTIFICATE_VERIFY   = 15;
    const message_type TLS_MSG_CLIENT_KEY_EXCHANGE  = 16;
    const message_type TLS_MSG_FINISHED             = 20;
    const message_type TLS_MSG_CERTIFICATE_STATUS   = 22;
    const message_type TLS_MSG_KEY_UPDATE           = 24;
    const message_type TLS_NSG_NEXT_PROTOCOL        = 67;  // Not IANA assigned
    const message_type TLS_MSG_MESSAGE_HASH         = 254; // synthetic message

    // TLS compression types.
    typedef uint8_t compression_method_type;
    const compression_method_type TLS_COMPRESSION_METHOD_NONE = 0;

    // TLS Elliptic Curve Point Formats
    // https://tools.ietf.org/html/rfc4492#section-5.1.2
    typedef uint8_t point_format_type;
    const point_format_type TLS_POINT_FORMAT_UNCOMPRESSED = 0;

    // TLS cipher suites
    // A list of cipher suite IDs that are, or have been, implemented by this
    // package.
    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
    typedef uint16_t cipher_suite_type;
    // TLS 1.0 - 1.2 cipher suites.
    const cipher_suite_type TLS_CIPHER_SUITE_UNKNOWN                      = 0x0000;
    const cipher_suite_type TLS_RSA_WITH_RC4_128_SHA                      = 0x0005;
    const cipher_suite_type TLS_RSA_WITH_3DES_EDE_CBC_SHA                 = 0x000a;
    const cipher_suite_type TLS_RSA_WITH_AES_128_CBC_SHA                  = 0x002f;
    const cipher_suite_type TLS_RSA_WITH_AES_256_CBC_SHA                  = 0x0035;
    const cipher_suite_type TLS_RSA_WITH_AES_128_CBC_SHA256               = 0x003c;
    const cipher_suite_type TLS_RSA_WITH_AES_128_GCM_SHA256               = 0x009c;
    const cipher_suite_type TLS_RSA_WITH_AES_256_GCM_SHA384               = 0x009d;
    const cipher_suite_type TLS_ECDHE_ECDSA_WITH_RC4_128_SHA              = 0xc007;
    const cipher_suite_type TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          = 0xc009;
    const cipher_suite_type TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          = 0xc00a;
    const cipher_suite_type TLS_ECDHE_RSA_WITH_RC4_128_SHA                = 0xc011;
    const cipher_suite_type TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           = 0xc012;
    const cipher_suite_type TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            = 0xc013;
    const cipher_suite_type TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            = 0xc014;
    const cipher_suite_type TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       = 0xc023;
    const cipher_suite_type TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         = 0xc027;
    const cipher_suite_type TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         = 0xc02f;
    const cipher_suite_type TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       = 0xc02b;
    const cipher_suite_type TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         = 0xc030;
    const cipher_suite_type TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       = 0xc02c;
    const cipher_suite_type TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = 0xcca8;
    const cipher_suite_type TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9;
    // TLS 1.3 cipher suites.
    const cipher_suite_type TLS_AES_128_GCM_SHA256                        = 0x1301;
    const cipher_suite_type TLS_AES_256_GCM_SHA384                        = 0x1302;
    const cipher_suite_type TLS_CHACHA20_POLY1305_SHA256                  = 0x1303;
    // TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
    // that the client is doing version fallback. See RFC 7507.
    const cipher_suite_type TLS_FALLBACK_SCSV                             = 0x5600;
    // Legacy names for the corresponding cipher suites with the correct _SHA256
    // suffix, retained for backward compatibility.
    const cipher_suite_type TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305          = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
    const cipher_suite_type TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305        = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;

    // TLS Certificate Status Type
    // https://tools.ietf.org/html/rfc3546
    typedef uint8_t certicate_status_type;
    const certicate_status_type TLS_OCSP_STATUS = 1;

    // TLS 1.3 PSK Key Exchange Modes. See RFC 8446, Section 4.2.9.
    typedef uint8_t psk_mode_type;
    const psk_mode_type TLS_PSK_MODE_PLAIN = 0;
    const psk_mode_type TLS_PSK_MODE_DHE   = 1;

    // TLS extension types.
    typedef uint16_t extension_type;
    const extension_type TLS_EXTENSION_SERVER_NAME               = 0;  // https://tools.ietf.org/html/rfc6066#section-3
    const extension_type TLS_EXTENSION_MAX_FRAGMENT_LENGTH       = 1;  // https://tools.ietf.org/html/rfc6066
    const extension_type TLS_EXTENSION_STATUS_REQUEST            = 5;  // https://tools.ietf.org/html/rfc4366#section-3.6
    const extension_type TLS_EXTENSION_SUPPORTED_GROUPS          = 10; // https://tools.ietf.org/html/rfc4492#section-5.1.1 https://tools.ietf.org/html/rfc8446#section-4.2.7
    const extension_type TLS_EXTENSION_SUPPORTED_POINTS          = 11; // https://tools.ietf.org/html/rfc4492#section-5.1.2
    const extension_type TLS_EXTENSION_SIGNATURE_ALGORITHMS      = 13; // https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1 https://tools.ietf.org/html/rfc8446#section-4.2.3
    const extension_type TLS_EXTENSION_ALPN                      = 16; // https://tools.ietf.org/html/rfc7301#section-3.1
    const extension_type TLS_EXTENSION_SCT                       = 18; // https://tools.ietf.org/html/rfc6962#section-3.3.1
    const extension_type TLS_EXTENSION_SESSION_TICKET            = 35; // https://tools.ietf.org/html/rfc5077#section-3.2
    const extension_type TLS_EXTENSION_PRE_SHARED_KEY            = 41; // https://tools.ietf.org/html/rfc8446#section-4.2.11
    const extension_type TLS_EXTENSION_EARLY_DATA                = 42; // https://tools.ietf.org/html/rfc8446#section-4.2.10
    const extension_type TLS_EXTENSION_SUPPORTED_VERSIONS        = 43; // https://tools.ietf.org/html/rfc8446#section-4.2.1
    const extension_type TLS_EXTENSION_COOKIE                    = 44; // https://tools.ietf.org/html/rfc8446#section-4.2.2
    const extension_type TLS_EXTENSION_PSK_MODES                 = 45; // https://tools.ietf.org/html/rfc8446#section-4.2.9
    const extension_type TLS_EXTENSION_CERTIFICATE_AUTHORITIES   = 47; // https://tools.ietf.org/html/rfc8446
    const extension_type TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT = 50; // https://tools.ietf.org/html/rfc8446#section-4.2.3
    const extension_type TLS_EXTENSION_KEY_SHARE                 = 51; // https://tools.ietf.org/html/rfc8446#section-4.2.8
    const extension_type TLS_EXTENSION_RENEGOTIATION_INFO        = 0xff01; // https://tools.ietf.org/html/rfc5746#section-3.2
    const extension_type TLS_EXTENSION_QUIC                      = 0xffa5;

    // TLS handshaker status.
    typedef int32_t handshake_status;
    const handshake_status HANDSHAKE_INIT                      = 0;
    const handshake_status HANDSHAKE_CLIENT_HELLO_SEND         = 1;
    const handshake_status HANDSHAKE_CLIENT_HELLO_RECV         = 2;
    const handshake_status HANDSHAKE_SERVER_HELLO_SEND         = 3;
    const handshake_status HANDSHAKE_SERVER_HELLO_RECV         = 4;
    const handshake_status HANDSHAKE_HELLO_REQUEST_SEND        = 5;
    const handshake_status HANDSHAKE_RETRY_HELLO_SEND          = 7;
    const handshake_status HANDSHAKE_RETRY_HELLO_RECV          = 8;
    const handshake_status HANDSHAKE_ENCRYPTED_EXTENSIONS_SEND = 9;
    const handshake_status HANDSHAKE_ENCRYPTED_EXTENSIONS_RECV = 10;
    const handshake_status HANDSHAKE_CARTIFICATE_REQUEST_SEND  = 11;
    const handshake_status HANDSHAKE_CARTIFICATE_REQUEST_RECV  = 12;
    const handshake_status HANDSHAKE_CARTIFICATE_SEND          = 13;
    const handshake_status HANDSHAKE_CARTIFICATE_RECV          = 14;
    const handshake_status HANDSHAKE_CARTIFICATE_VERIFY_SEND   = 15;
    const handshake_status HANDSHAKE_CARTIFICATE_VERIFY_RECV   = 16;
    const handshake_status HANDSHAKE_FINISHED_SEND             = 17;
    const handshake_status HANDSHAKE_FINISHED_RECV             = 18;
    const handshake_status HANDSHAKE_SUCCESS                   = 100;

	// downgradeCanaryTLS12 or downgradeCanaryTLS11 is embedded in the server
	// random as a downgrade protection if the server would be capable of
	// negotiating a higher version. See RFC 8446, Section 4.1.3.
    #define DOWNGRRADE_CANARY_TLS11             "DOWNGRD\x00"
	#define DOWNGRRADE_CANARY_TLS12             "DOWNGRD\x01"

	#define RESUMPTION_BINDER_LABEL             "res binder"
	#define CLIENT_HANDSHAKE_TRAFFIC_LABEL      "c hs traffic"
	#define SERVER_HANDSHAKE_TRAFFIC_LABEL      "s hs traffic"
	#define CLIENT_APPLICATION_TRAFFIC_LABEL    "c ap traffic"
	#define SERVER_APPLICATION_TRAFFIC_LABEL    "s ap traffic"
	#define EXPORTER_LABEL                      "exp master"
	#define RESUMPTION_LABEL                    "res master"
	#define TRAFFIC_UPDATE_LABEL                "traffic upd"

	#define SERVER_SIGNATURE_CONTEXT            "TLS 1.3, server CertificateVerify\x00"
	#define CLIENT_SIGNATURE_CONTEXT            "TLS 1.3, client CertificateVerify\x00"

    // TLS 1.3 supported cipher suites
    const std::vector<cipher_suite_type> supported_cipher_suites = {
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256
    };

    // TLS 1.3 supported curve groups
    const std::vector<ssl::curve_group_type> supported_curve_groups = {
        ssl::TLS_CURVE_X25519,
        ssl::TLS_CURVE_P256,
        ssl::TLS_CURVE_P384,
        ssl::TLS_CURVE_P521
    };

    // TLS 1.3 supported signature schemes
    const std::vector<ssl::signature_scheme> supported_signature_schemes = {
        ssl::TLS_SIGN_SCHE_PSSWITHSHA256,
        ssl::TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256,
        ssl::TLS_SIGN_SCHE_PSSWITHSHA384,
        ssl::TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384,
        ssl::TLS_SIGN_SCHE_PSSWITHSHA512,
        ssl::TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512,
        ssl::TLS_SIGN_SCHE_ED25519
    };

    // Retry hello request fixed random.
    const uint8_t hello_retry_request_random[] = {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    };

    const uint8_t signature_padding[] = {
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    };

    /*********************************************************************************
     * TLS config.
     ********************************************************************************/
    struct config {
        std::string cert_pem;
        std::string server_name;
        std::string alpn;
    };
    DEFINE_RAW_POINTER_TYPE(config)

    /*********************************************************************************
     * TLS cipher suite context.
     ********************************************************************************/
    struct cipher_suite_context {
        ssl::hash_algorithm algo;
        cipher_suite_type type;
        int32_t key_len;
    };
    DEFINE_RAW_POINTER_TYPE(cipher_suite_context)

    /*********************************************************************************
     * TLS connection session.
     ********************************************************************************/
    struct connection_session {
        // TLS verson
        version_type version;

        // TLS ecdhe context
        ssl::ecdhe_context_ptr ecdhe_ctx;

        // TLS cipher suite context
        cipher_suite_context_ptr cipher_suite_ctx;

        // 0-RTT enable status
        bool enable_zero_rtt;

        // TLS server name
        std::string server_name;

        // Application protocol
        std::string alpn;

        // TLS ocsp staple
        std::string ocsp_staple;

        // TLS signed certificate timestamp
        std::vector<std::string> scts;

        std::string master_secret;
        std::string client_secret;
        std::string server_secret;
        std::string traffic_secret;
        std::string handshake_secret;
        std::string export_master_secret;

        // Certificates
        std::vector<ssl::x509_certificate> certs;

        // Peer certificates
        std::vector<ssl::x509_certificate> peer_certs;
    };
    DEFINE_RAW_POINTER_TYPE(connection_session)

    /*********************************************************************************
     * Init connection session
     ********************************************************************************/
    void init_connection_session(connection_session_ptr session);

    /*********************************************************************************
     * Rest connection session
     ********************************************************************************/
    void reset_connection_session(connection_session_ptr session);

}
}
}
}

#endif