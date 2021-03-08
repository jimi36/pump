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
 
#ifndef pump_protocol_quic_tls_handshake_messages_h
#define pump_protocol_quic_tls_handshake_messages_h

#include <map>
#include <string>
#include <vector>

#include "pump/types.h"

// TLS handshake message types.
typedef uint8_t tls_message_type;
#define TLS_MSG_HELLO_REQUEST        0
#define TLS_MSG_CLIENT_HELLO         1
#define TLS_MSG_SERVER_HELLO         2
#define TLS_MSG_NEW_SESSION_TICKET   4
#define TLS_MSG_END_OF_EARLY_DATA    5
#define TLS_MSG_ENCRYPTED_EXTENSIONS 8
#define TLS_MSG_CERTIFACE            11
#define TLS_MSG_SERVER_KEY_EXCHANGE  12
#define TLS_MSG_CERTIFICATE_REQUEST  13
#define TLS_MSG_SERVER_HELLO_DONE    14
#define TLS_MSG_CERIFICATE_VERIFY    15
#define TLS_MSG_CLIENT_KEY_EXCHANGE  16
#define TLS_MSG_FINISHED             20
#define TLS_MSG_CERTIFICATE_STATUS   22
#define TLS_MSG_KEY_UPDATE           24
#define TLS_NSG_NEXT_PROTOCOL        67  // Not IANA assigned
#define TLS_MSG_MESSAGE_HASH         254 // synthetic message

// TLS verison.
typedef uint16_t tls_version_type;
#define TLS_VERSION_10 0x0301
#define TLS_VSERVER_11 0x0302
#define TLS_VSERVER_12 0x0303
#define TLS_VSERVER_13 0x0304

// TLS cipher suites
typedef uint16_t tls_cipher_suite_type;

// TLS compression types.
typedef uint8_t tls_compression_method_type;
#define TLS_COMPRESSION_METHOD_NONE 0

// TLS Elliptic Curve Point Formats
// https://tools.ietf.org/html/rfc4492#section-5.1.2
typedef uint8_t tls_point_format_type;
#define TLS_POINT_FORMAT_UNCOMPRESSED 0

// TLS curve group types.
typedef uint16_t tls_group_type;
#define TLS_GROUP_P256   23
#define TLS_GROUP_P384   24
#define TLS_GROUP_P2521  25
#define TLS_GROUP_X25519 29

// TLS signature scheme types
typedef uint16_t tls_signature_scheme_type;
// RSASSA-PKCS1-v1_5 algorithms.
#define TLS_SIGN_SCHEME_PKCS1WITHSHA256        0x0401
#define TLS_SIGN_SCHEME_PKCS1WITHSHA384        0x0501
#define TLS_SIGN_SCHEME_PKCS1WITHSHA512        0x0601
// RSASSA-PSS algorithms with public key OID rsaEncryption.
#define TLS_SIGN_SCHEME_PSSWITHSHA256          0x0804
#define TLS_SIGN_SCHEME_PSSWITHSHA384          0x0805
#define TLS_SIGN_SCHEME_PSSWITHSHA512          0x0806
// ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
#define TLS_SIGN_SCHEME_ECDSAWITHP256AndSHA256 0x0403
#define TLS_SIGN_SCHEME_ECDSAWITHP384AndSHA384 0x0503
#define TLS_SIGN_SCHEME_ECDSAWITHP521AndSHA512 0x0603
// EdDSA algorithms.
#define TLS_SIGN_SCHEME_ED25519                0x0807
// Legacy signature and hash algorithms for TLS 1.2.
#define TLS_SIGN_SCHEME_PKCS1WITHSHA1          0x0201
#define TLS_SIGN_SCHEME_ECDSAWITHSHA1          0x0203

// TLS 1.3 PSK Key Exchange Modes. See RFC 8446, Section 4.2.9.
typedef uint8_t tls_psk_mode_type;
#define TLS_PSK_MODE_PLAIN 0
#define TLS_PSK_MODE_DHE   1

// TLS extension types.
typedef uint16_t tls_extension_type;
#define TLS_EXTENSION_SERVER_NAME               0  // https://tools.ietf.org/html/rfc6066#section-3
#define TLS_EXTENSION_MAX_FRAGMENT_LENGTH       1  // https://tools.ietf.org/html/rfc6066
#define TLS_EXTENSION_STATUS_REQUEST            5  // https://tools.ietf.org/html/rfc4366#section-3.6
#define TLS_EXTENSION_SUPPORTED_GROUPS          10 // https://tools.ietf.org/html/rfc4492#section-5.1.1 https://tools.ietf.org/html/rfc8446#section-4.2.7
#define TLS_EXTENSION_SUPPORTED_POINTS          11 // https://tools.ietf.org/html/rfc4492#section-5.1.2
#define TLS_EXTENSION_SIGNATURE_ALGORITHMS      13 // https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1 https://tools.ietf.org/html/rfc8446#section-4.2.3
#define TLS_EXTENSION_ALPN                      16 // https://tools.ietf.org/html/rfc7301#section-3.1
#define TLS_EXTENSION_SCT                       18 // https://tools.ietf.org/html/rfc6962#section-3.3.1
#define TLS_EXTENSION_SESSION_TICKET            35 // https://tools.ietf.org/html/rfc5077#section-3.2
#define TLS_EXTENSION_PRE_SHARED_KEY            41 // https://tools.ietf.org/html/rfc8446#section-4.2.11
#define TLS_EXTENSION_EARLY_DATA                42 // https://tools.ietf.org/html/rfc8446#section-4.2.10
#define TLS_EXTENSION_SUPPORTED_VERSIONS        43 // https://tools.ietf.org/html/rfc8446#section-4.2.1
#define TLS_EXTENSION_COOKIE                    44 // https://tools.ietf.org/html/rfc8446#section-4.2.2
#define TLS_EXTENSION_PSK_MODES                 45 // https://tools.ietf.org/html/rfc8446#section-4.2.9
#define TLS_EXTENSION_CERTIFICATE_AUTHORITIES   47 // https://tools.ietf.org/html/rfc8446
#define TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT 50 // https://tools.ietf.org/html/rfc8446#section-4.2.3
#define TLS_EXTENSION_KEY_SHARE                 51 // https://tools.ietf.org/html/rfc8446#section-4.2.8
#define TLS_EXTENSION_RENEGOTIATION_INFO        0xff01 // https://tools.ietf.org/html/rfc5746#section-3.2
#define TLS_EXTENSION_QUIC                      0xffa5

struct key_share {
    tls_group_type group;
    std::string data;
};

struct psk_identity {
    std::string identity;
    uint32_t obfuscated_ticket_age;
 
};

struct extension {
    uint16_t type;
    std::string data;
};

struct client_hello_message {
    // In previous versions of TLS, this field was used for
    // version negotiation and represented the highest version number
    // supported by the client. Experience has shown that many servers
    // do not properly implement version negotiation, leading to "version
    // intolerance" in which the server rejects an otherwise acceptable
    // ClientHello with a version number higher than it supports.  In
    // TLS 1.3, the client indicates its version preferences in the
    // "supported_versions" extension (Section 4.2.1) and the
    // legacy_version field MUST be set to 0x0303, which is the version
    // number for TLS 1.2. TLS 1.3 ClientHellos are identified as having
    // a legacy_version of 0x0303 and a supported_versions extension
    // present with 0x0304 as the highest version indicated therein.
    // https://tools.ietf.org/html/rfc5246#section-7.4.1.2
    tls_version_type legacy_version;
    
    // A 32-bytes random structure.
    // https://tools.ietf.org/html/rfc5246#section-7.4.1.2
    uint8_t random[32];
    
    // A 32-bytes session id, but this field maybe empty.
    // https://tools.ietf.org/html/rfc5077
    // https://tools.ietf.org/html/rfc5246#section-7.4.1.2
    // https://tools.ietf.org/html/rfc8446#section-4.1.2
    std::string session_id;
    
    // A list of the symmetric cipher options supported by the 
    // client, specifically the record protection algorithm (including
    // secret key length) and a hash to be used with HKDF, in descending
    // order of client preference.
    // https://tools.ietf.org/html/rfc5246#appendix-A.5
    // https://tools.ietf.org/html/rfc8446#section-4.1.2
    std::vector<tls_cipher_suite_type> cipher_suites;
    
    // This is a list of the compression methods supported by the client,
    // sorted by client preference.
    // https://tools.ietf.org/html/rfc5246#section-7.4.1.2
    // https://tools.ietf.org/html/rfc8446#section-4.1.2
    std::vector<tls_compression_method_type> compression_methods;

    // Clients MAY request extended functionality from servers by sending
    // data in the extensions field.  The actual "Extension" format is
    // defined in https://tools.ietf.org/html/rfc5246#section-7.4.1.4
    //std::vector<handshake_extension> extensions;

    // Extension field.
    // In order to provide any of the server names, clients MAY include an
    // extension of type "server_name" in the (extended) client hello.
    // https://tools.ietf.org/html/rfc6066#section-3
    std::string server_name;

    // Extension field.
    // Constrained clients may wish to use a certificate-status protocol
    // such as OCSP [OCSP] to check the validity of server certificates, in
    // order to avoid transmission of CRLs and therefore save bandwidth on
    // constrained networks. This extension allows for such information to
    // be sent in the TLS handshake, saving roundtrips and resources.
    // https://tools.ietf.org/html/rfc4366#section-3.6
    bool is_support_ocsp;

    // Extension field.
    // When sent by the client, the "supported_groups" extension indicates
    // the named groups which the client supports for key exchange, ordered
    // from most preferred to least preferred.
    // Note: In versions of TLS prior to TLS 1.3, this extension was named
    // "elliptic_curves" and only contained elliptic curve groups.  See
    // [RFC8422] and [RFC7919]. This extension was also used to negotiate
    // ECDSA curves.  Signature algorithms are now negotiated independently
    // (see Section 4.2.3).
    // https://tools.ietf.org/html/rfc4492#section-5.1.1
    // https://tools.ietf.org/html/rfc8446#section-4.2.7
    std::vector<tls_group_type> supported_groups;

    // Extension field.
    // Three point formats are included in the definition of ECPointFormat
    // above. The uncompressed point format is the default format in that
    // implementations of this document MUST support it for all of their
    // supported curves. Compressed point formats reduce bandwidth by
    // including only the x-coordinate and a single bit of the y-coordinate
    // of the point. Implementations of this document MAY support the
    // ansiX962_compressed_prime and ansiX962_compressed_char2 formats,
    // where the former applies only to prime curves and the latter applies
    // only to characteristic-2 curves.
    // https://tools.ietf.org/html/rfc4492#section-5.1.2
    std::vector<tls_point_format_type> supported_points;

    // Extension field.
    // If the client possesses a ticket that it wants to use to resume a
    // session, then it includes the ticket in the SessionTicket extension
    // in the ClientHello. If the client does not have a ticket and is
    // prepared to receive one in the NewSessionTicket handshake message,
    // then it MUST include a zero-length ticket in the SessionTicket
    // extension. If the client is not prepared to receive a ticket in the
    // NewSessionTicket handshake message, then it MUST NOT include a
    // SessionTicket extension unless it is sending a non-empty ticket it
    // received through some other means from the server.
    // https://tools.ietf.org/html/rfc5077#section-3.2
    bool is_support_session_ticket;
    std::string session_ticket;

    // Extension field.
    // The client uses the "signature_algorithms" extension to indicate to
    // the server which signature/hash algorithm pairs may be used in
    // digital signatures. The "extension_data" field of this extension
    // contains a "supported_signature_algorithms" value.
    // https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
    // https://tools.ietf.org/html/rfc8446#section-4.2.3
    std::vector<tls_signature_scheme_type> supported_signature_algorithms;

    // Extension field.
    // The "signature_algorithms_cert" extension was added to allow
    // implementations which supported different sets of algorithms for
    // certificates and in TLS itself to clearly signal their capabilities.
    // TLS 1.2 implementations SHOULD also process this extension.
    // Implementations which have the same policy in both cases MAY omit the
    // "signature_algorithms_cert" extension.
    // https://tools.ietf.org/html/rfc8446#section-4.2.3
    std::vector<tls_signature_scheme_type> supported_signature_algorithms_certs;

    // Extension field.
    // A new TLS extension, "renegotiation_info" (with extension type 0xff01), 
    // which contains a cryptographic binding to the enclosing TLS connection 
    // (if any) for which the renegotiation is being performed.
    // https://tools.ietf.org/html/rfc5746#section-3.2
    bool is_support_renegotiation_info;
    std::string renegotiation_info;

    // Extension field.
    // A new extension type ("application_layer_protocol_negotiation(16)")
    // is defined and MAY be included by the client in its "ClientHello"
    // message.
    // https://tools.ietf.org/html/rfc7301#section-3.1
    std::vector<std::string> alpns;

    // Extension field.
    // The SCT can be sent during the TLS handshake using a TLS extension
    // with type "signed_certificate_timestamp".
    // Clients that support the extension SHOULD send a ClientHello
    // extension with the appropriate type and empty "extension_data".
    // https://tools.ietf.org/html/rfc6962#section-3.3.1
    bool is_support_sct;

    // Extension field.
    // The "supported_versions" extension is used by the client to indicate
    // which versions of TLS it supports and by the server to indicate which
    // version it is using. The extension contains a list of supported
    // versions in preference order, with the most preferred version first.
    // Implementations of this specification MUST send this extension in the
    // ClientHello containing all versions of TLS which they are prepared to
    // negotiate (for this specification, that means minimally 0x0304, but
    // if previous versions of TLS are allowed to be negotiated, they MUST
    // be present as well).
    // https://tools.ietf.org/html/rfc8446#section-4.2.1
    std::vector<tls_version_type> supported_versions;

    // Extension field.
    // Cookies serve two primary purposes:
    // -  Allowing the server to force the client to demonstrate
    //    reachability at their apparent network address (thus providing a
    //    measure of DoS protection).  This is primarily useful for
    //    non-connection-oriented transports (see [RFC6347] for an example
    //    of this).
    // -  Allowing the server to offload state to the client, thus allowing
    //    it to send a HelloRetryRequest without storing any state.  The
    //    server can do this by storing the hash of the ClientHello in the
    //    HelloRetryRequest cookie (protected with some suitable integrity
    //    protection algorithm).
    // https://tools.ietf.org/html/rfc8446#section-4.2.2
    std::string cookie;

    // Extension field.
    // The "key_share" extension contains the endpoint's cryptographic
    // parameters. Clients MAY send an empty client_shares vector in order 
    // to request group selection from the server, at the cost of an additional
    // round trip.
    // https://tools.ietf.org/html/rfc8446#section-4.2.8
    std::vector<key_share> key_shares;

    // Extension field.
    // When a PSK is used and early data is allowed for that PSK, the client
    // can send Application Data in its first flight of messages.  If the
    // client opts to do so, it MUST supply both the "pre_shared_key" and
    // "early_data" extensions.
    // https://tools.ietf.org/html/rfc8446#section-4.2.10
    bool is_support_early_data;

    // Extension field.
    // A client MUST provide a "psk_key_exchange_modes" extension if it
    // offers a "pre_shared_key" extension.  If clients offer
    // "pre_shared_key" without a "psk_key_exchange_modes" extension,
    // servers MUST abort the handshake.  Servers MUST NOT select a key
    // exchange mode that is not listed by the client.  This extension also
    // restricts the modes for use with PSK resumption.  Servers SHOULD NOT
    // send NewSessionTicket with tickets that are not compatible with the
    // advertised modes; however, if a server does so, the impact will just
    // be that the client's attempts at resumption fail.
    // https://tools.ietf.org/html/rfc8446#section-4.2.9
    std::vector<tls_psk_mode_type> psk_modes;

    // Extension field.
    // Additional extensions.
    std::vector<extension> additional_extensions;

    // Extension field.
    // The "pre_shared_key" extension is used to negotiate the identity of
    // the pre-shared key to be used with a given handshake in association
    // with PSK key establishment.
    // The "pre_shared_key" extension MUST be the last extension in the
    // ClientHello (this facilitates implementation as described below).
    // Servers MUST check that it is the last extension and otherwise fail
    // the handshake with an "illegal_parameter" alert.
    // https://tools.ietf.org/html/rfc8446#section-4.2.11
    std::vector<psk_identity> psk_identities;
    std::vector<std::string> psk_binders;
};

int32_t pack_client_hello(const client_hello_message *msg, uint8_t *buf, int32_t max_size);

int32_t unpack_client_hello(const uint8_t *buf, int32_t max_size, client_hello_message *msg);

struct server_hello_message {
    // In previous versions of TLS, this field was used for
    // version negotiation and represented the selected version number
    // for the connection.  Unfortunately, some middleboxes fail when
    // presented with new values.  In TLS 1.3, the TLS server indicates
    // its version using the "supported_versions" extension
    // (Section 4.2.1), and the legacy_version field MUST be set to
    // 0x0303, which is the version number for TLS 1.2.  (See Appendix D
    // for details about backward compatibility.)
    tls_version_type legacy_version;

    // This structure is generated by the server and MUST be
    // independently generated from the ClientHello.random.
    // https://tools.ietf.org/html/rfc5246#section-7.4.1.3
    uint8_t random[32];

    // This is the identity of the session corresponding to this
    // connection.  If the ClientHello.session_id was non-empty, the
    // server will look in its session cache for a match.  If a match is
    // found and the server is willing to establish the new connection
    // using the specified session state, the server will respond with
    // the same value as was supplied by the client. This indicates a
    // resumed session and dictates that the parties must proceed
    // directly to the Finished messages. Otherwise, this field will
    // contain a different value identifying the new session. The server
    // may return an empty session_id to indicate that the session will
    // not be cached and therefore cannot be resumed. If a session is
    // resumed, it must be resumed using the same cipher suite it was
    // originally negotiated with. Note that there is no requirement
    // that the server resume any session even if it had formerly
    // provided a session_id. Clients MUST be prepared to do a full
    // negotiation -- including negotiating new cipher suites -- during
    // any handshake.
    // https://tools.ietf.org/html/rfc5077
    // https://tools.ietf.org/html/rfc5246#section-7.4.1.3
    // https://tools.ietf.org/html/rfc8446#section-4.1.2
    std::string session_id;

    // The single cipher suite selected by the server from the list in
    // ClientHello.cipher_suites. For resumed sessions, this field is
    // the value from the state of the session being resumed.
    // https://tools.ietf.org/html/rfc5246#section-7.4.1.3
    tls_cipher_suite_type cipher_suite;

    // The single compression algorithm selected by the server from the
    // list in ClientHello.compression_methods.  For resumed sessions,
    // this field is the value from the resumed session state.
    // https://tools.ietf.org/html/rfc5246#section-7.4.1.3
    // https://tools.ietf.org/html/rfc8446#section-4.1.2
    tls_compression_method_type compression_method;

    // Extension field.
    // Servers that receive a client hello containing the "status_request"
    // extension MAY return a suitable certificate status response to the
    // client along with their certificate. If OCSP is requested, they
    // SHOULD use the information contained in the extension when selecting
    // an OCSP responder and SHOULD include request_extensions in the OCSP
    // request.
    // https://tools.ietf.org/html/rfc4366#section-3.6
    bool is_support_ocsp;

    // Extension field.
    // Three point formats are included in the definition of ECPointFormat
    // above. The uncompressed point format is the default format in that
    // implementations of this document MUST support it for all of their
    // supported curves. Compressed point formats reduce bandwidth by
    // including only the x-coordinate and a single bit of the y-coordinate
    // of the point. Implementations of this document MAY support the
    // ansiX962_compressed_prime and ansiX962_compressed_char2 formats,
    // where the former applies only to prime curves and the latter applies
    // only to characteristic-2 curves.
    // https://tools.ietf.org/html/rfc4492#section-5.1.2
    std::vector<tls_point_format_type> supported_points;

    // Extension field.
    // The server uses a zero-length SessionTicket extension to indicate to
    // the client that it will send a new session ticket using the
    // NewSessionTicket handshake message described in Section 3.3.  The
    // server MUST send this extension in the ServerHello if it wishes to
    // issue a new ticket to the client using the NewSessionTicket handshake
    // message.  The server MUST NOT send this extension if it does not
    // receive one in the ClientHello.
    // If the server fails to verify the ticket, then it falls back to
    // performing a full handshake.  If the ticket is accepted by the server
    // but the handshake fails, the client SHOULD delete the ticket.
    // https://tools.ietf.org/html/rfc5077#section-3.2
    bool is_support_session_ticket;

    // Extension field.
    // A new TLS extension, "renegotiation_info" (with extension type 0xff01), 
    // which contains a cryptographic binding to the enclosing TLS connection 
    // (if any) for which the renegotiation is being performed.
    // https://tools.ietf.org/html/rfc5746#section-3.2
    bool is_support_renegotiation_info;
    std::string renegotiation_info;

    // Extension field.
    // Servers that receive a ClientHello containing the
    // "application_layer_protocol_negotiation" extension MAY return a
    // suitable protocol selection response to the client. The server will
    // ignore any protocol name that it does not recognize. A new
    // ServerHello extension type
    // https://tools.ietf.org/html/rfc7301#section-3.1
    std::string alpn;

    // Extension field.
    // The SCT can be sent during the TLS handshake using a TLS extension
    // with type "signed_certificate_timestamp".
    // Servers MUST only send SCTs to clients who have indicated support for
    // the extension in the ClientHello, in which case the SCTs are sent by
    // setting the "extension_data" to a "SignedCertificateTimestampList".
    // https://tools.ietf.org/html/rfc6962#section-3.3.1
    std::vector<std::string> scts;

    // Extension field.
    // A server which negotiates a version of TLS prior to TLS 1.3 MUST set
    // ServerHello.version and MUST NOT send the "supported_versions"
    // extension. A server which negotiates TLS 1.3 MUST respond by sending
    // a "supported_versions" extension containing the selected version
    // value (0x0304). It MUST set the ServerHello.legacy_version field to
    // 0x0303 (TLS 1.2).
    // https://tools.ietf.org/html/rfc8446#section-4.2.1
    tls_version_type supported_version;

    // Extension field.
    //  If using (EC)DHE key establishment, servers offer exactly one
    // KeyShareEntry in the ServerHello.  This value MUST be in the same
    // group as the KeyShareEntry value offered by the client that the
    // server has selected for the negotiated key exchange.  Servers
    // MUST NOT send a KeyShareEntry for any group not indicated in the
    // client's "supported_groups" extension and MUST NOT send a
    // KeyShareEntry when using the "psk_ke" PskKeyExchangeMode.  If using
    // (EC)DHE key establishment and a HelloRetryRequest containing a
    // "key_share" extension was received by the client, the client MUST
    // verify that the selected NamedGroup in the ServerHello is the same as
    // that in the HelloRetryRequest.  If this check fails, the client MUST
    // abort the handshake with an "illegal_parameter" alert.
    // https://tools.ietf.org/html/rfc8446#section-4.2.8
    bool selected_key_share;
    key_share key_share;

    // Extension field.
    // Upon receipt of this extension in a HelloRetryRequest, the client
    // MUST verify that (1) the selected_group field corresponds to a group
    // which was provided in the "supported_groups" extension in the
    // original ClientHello and (2) the selected_group field does not
    // correspond to a group which was provided in the "key_share" extension
    // in the original ClientHello. If either of these checks fails, then
    // the client MUST abort the handshake with an "illegal_parameter"
    // alert.  Otherwise, when sending the new ClientHello, the client MUST
    // replace the original "key_share" extension with one containing only a
    // new KeyShareEntry for the group indicated in the selected_group field
    // of the triggering HelloRetryRequest.
    // https://tools.ietf.org/html/rfc8446#section-4.2.8
    tls_group_type selected_group;

    // Extension field.
    // Prior to accepting PSK key establishment, the server MUST validate
    // the corresponding binder value (see Section 4.2.11.2 below).  If this
    // value is not present or does not validate, the server MUST abort the
    // handshake.  Servers SHOULD NOT attempt to validate multiple binders;
    // rather, they SHOULD select a single PSK and validate solely the
    // binder that corresponds to that PSK.  See Section 8.2 and
    // Appendix E.6 for the security rationale for this requirement.  In
    // order to accept PSK key establishment, the server sends a
    // "pre_shared_key" extension indicating the selected identity.
    // https://tools.ietf.org/html/rfc8446#section-4.2.11
    bool selected_psk_identity;
    uint16_t psk_identity;

    // Extension field.
    // When a server is operating statelessly, it may receive an unprotected
    // record of type change_cipher_spec between the first and second
    // ClientHello (see Section 5). Since the server is not storing any
    // state, this will appear as if it were the first message to be
    // received. Servers operating statelessly MUST ignore these records.
    // https://tools.ietf.org/html/rfc8446#section-4.2.2
    std::string cookie;
};

int32_t pack_server_hello(const server_hello_message *msg, uint8_t *buf, int32_t max_size);

int32_t unpack_server_hello(const uint8_t *buf, int32_t size, server_hello_message *msg);

struct encrypted_extensions_message {
    // Extension field.
    // https://tools.ietf.org/html/rfc7301#section-3.1
    std::string alpn;

    // Extension field.
    // https://tools.ietf.org/html/rfc8446#section-4.2.10
    bool is_support_early_data;

    // Extension field.
    // Additional extensions.
    std::vector<extension> additional_extensions;
};

int32_t pack_encrypted_extensions(const encrypted_extensions_message *msg, uint8_t *buf, int32_t max_size);

int32_t unpack_encrypted_extensions(const uint8_t *buf, int32_t size, encrypted_extensions_message *msg);

struct end_early_data_message {
};

int32_t pack_end_early_data(const end_early_data_message *msg, uint8_t *buf, int32_t max_size);

int32_t unpack_end_early_data(const uint8_t *buf, int32_t size, end_early_data_message *msg);

struct key_update_message {
    bool update_requested;
};

int32_t pack_key_update(const key_update_message *msg, uint8_t *buf, int32_t max_size);

int32_t unpack_key_update(const uint8_t *buf, int32_t size, key_update_message *msg);

#endif
