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
 
#ifndef pump_proto_quic_tls_messages_h
#define pump_proto_quic_tls_messages_h

#include <map>
#include <vector>

#include "pump/toolkit/buffer.h"
#include "pump/proto/quic/tls/types.h"

namespace pump {
namespace proto {
namespace quic {
namespace tls {

    using toolkit::io_buffer;

    /*********************************************************************************
     * TLS handshake message struct.
     ********************************************************************************/
    struct handshake_message {
        message_type tp;
        void *msg;
        std::string packed;
    };

    /*********************************************************************************
     * New handshake message.
     ********************************************************************************/
    LIB_PUMP handshake_message* new_handshake_message(message_type type);

    /*********************************************************************************
     * Delete handshake message.
     ********************************************************************************/
    LIB_PUMP void delete_handshake_message(handshake_message *msg);

    /*********************************************************************************
     * Pack handshake message.
     ********************************************************************************/
    LIB_PUMP bool pack_handshake_message(handshake_message *msg);

    /*********************************************************************************
     * Unpack handshake message.
     ********************************************************************************/
    LIB_PUMP bool unpack_handshake_message(io_buffer *iob, handshake_message *msg);

    /*********************************************************************************
     * TLS handshake key stare struct.
     ********************************************************************************/
    struct key_share {
        ssl::curve_group_type group;
        std::string data;
    };

    /*********************************************************************************
     * TLS handshake psk indentity struct.
     ********************************************************************************/
    struct psk_identity {
        std::string identity;
        uint32_t obfuscated_ticket_age;
    };

    /*********************************************************************************
     * TLS handshake extension struct.
     ********************************************************************************/
    struct extension {
        extension_type type;
        std::string data;
    };

    /*********************************************************************************
     * The hello request message MAY be sent by the server at any time. Hello request 
     * is a simple notification that the client should begin the negotiation process 
     * a new by sending a client hello message when convenient. This message will be
     * ignored by the client if the client is currently negotiating a session. This
     * message may be ignored by the client if it does not wish to renegotiate a 
     * session, or the client may, if it wishes, respond with a no_renegotiation 
     * alert.  Since handshake messages are intended to have transmission precedence 
     * over application data, it is expected that the negotiation will begin before 
     * no more than a few records are received from the client.  If the server sends
     * a hello request but does not receive a client hello in response, it may close
     * the connection with a fatal alert.
     * https://tools.ietf.org/html/rfc4346#section-7.4.1.1
     ********************************************************************************/
    struct hello_req_message {
    };

    /*********************************************************************************
     * New hello request message.
     ********************************************************************************/
    LIB_PUMP hello_req_message* new_hello_req_message();

    /*********************************************************************************
     * Pack hello request message.
     ********************************************************************************/
    LIB_PUMP bool pack_hello_req_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack hello request message.
     ********************************************************************************/
    LIB_PUMP bool unpack_hello_req_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * When client first connects to a server, it is REQUIRED to send the ClientHello
     * as its first TLS message. The client will also send a ClientHello when the
     * server has responded to its ClientHello with a HelloRetryRequest.
     * https://tools.ietf.org/html/rfc8446#section-4.1.2
     ********************************************************************************/
    struct client_hello_message {
        // In TLS 1.3, the client indicates its version preferences in the
        // "supported_versions" extension and the legacy_version field MUST be set
        // to 0x0303, which is the version number for TLS 1.2. TLS 1.3 ClientHellos
        // are identified as having a legacy_version of 0x0303 and a 
        // supported_versions extension present with 0x0304 as the highest version
        // indicated therein.
        // https://tools.ietf.org/html/rfc5246#section-7.4.1.2
        version_type legacy_version;
        
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
        std::vector<cipher_suite_type> cipher_suites;
        
        // This is a list of the compression methods supported by the client,
        // sorted by client preference.
        // https://tools.ietf.org/html/rfc5246#section-7.4.1.2
        // https://tools.ietf.org/html/rfc8446#section-4.1.2
        std::vector<compression_method_type> compression_methods;

        // Extension field.
        // In order to provide any of the server names, clients MAY include an
        // extension of type "server_name" in the (extended) client hello.
        // https://tools.ietf.org/html/rfc6066#section-3
        std::string server_name;

        // Extension field.
        // Constrained clients may wish to use a certificate-status proto such as 
        // OCSP [OCSP] to check the validity of server certificates, in order to 
        // avoid transmission of CRLs and therefore save bandwidth on constrained
        // networks. This extension allows for such information to be sent in the TLS
        // handshake, saving roundtrips and resources.
        // https://tools.ietf.org/html/rfc4366#section-3.6
        bool is_support_ocsp_stapling;

        // Extension field.
        // When sent by the client, the "supported_groups" extension indicates the 
        // named groups which the client supports for key exchange, ordered from
        // most preferred to least preferred.
        // Note: In versions of TLS prior to TLS 1.3, this extension was named
        // "elliptic_curves" and only contained elliptic curve groups. See [RFC8422]
        // and [RFC7919]. This extension was also used to negotiate ECDSA curves.
        // Signature algorithms are now negotiated independently.
        // https://tools.ietf.org/html/rfc4492#section-5.1.1
        // https://tools.ietf.org/html/rfc8446#section-4.2.7
        std::vector<ssl::curve_group_type> supported_groups;

        // Extension field.
        // Three point formats are included in the definition of ECPointFormat above.
        // The uncompressed point format is the default format in that implementations
        // of this document MUST support it for all of their supported curves.
        // https://tools.ietf.org/html/rfc4492#section-5.1.2
        std::vector<point_format_type> supported_point_formats;

        // Extension field.
        // If the client possesses a ticket that it wants to use to resume a session, 
        // then it includes the ticket in SessionTicket extension in the ClientHello.
        // If the client does not have a ticket and is prepared to receive one in the
        // NewSessionTicket handshake message, then it MUST include a zero-length
        // ticket in the SessionTicket extension. If the client is not prepared to
        // receive a ticket in the NewSessionTicket handshake message, then it MUST
        // NOT include a SessionTicket extension unless it is sending a non-empty 
        // ticket it received through some other means from the server.
        // https://tools.ietf.org/html/rfc5077#section-3.2
        bool is_support_session_ticket;
        std::string session_ticket;

        // Extension field.
        // The client uses the "signature_algorithms" extension to indicate to the 
        // server which sign/hash algorithm pairs may be used in digital signatures.
        // The "extension_data" field of this extension contains a 
        // "supported_signature_algorithms" value.
        // https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
        // https://tools.ietf.org/html/rfc8446#section-4.2.3
        std::vector<ssl::signature_scheme> signature_schemes;

        // Extension field.
        // The "signature_algorithms_cert" extension was added to allow implementations
        // which supported different sets of algorithms for certificates and in TLS
        // itself to clearly signal their capabilities. TLS 1.2 implementations SHOULD
        // also process this extension. Implementations which have the same policy in 
        // both cases MAY omit the "signature_algorithms_cert" extension.
        // https://tools.ietf.org/html/rfc8446#section-4.2.3
        std::vector<ssl::signature_scheme> signature_scheme_certs;

        // Extension field.
        // A new TLS extension "renegotiation_info" which contains a cryptographic
        // binding to the enclosing TLS connection (if any) for which the renegotiation
        // is being performed.
        // https://tools.ietf.org/html/rfc5746#section-3.2
        bool is_support_renegotiation_info;
        std::string renegotiation_info;

        // Extension field.
        // A new extension "application_layer_proto_negotiation" is defined and MAY
        // be included by the client in its "ClientHello" message.
        // https://tools.ietf.org/html/rfc7301#section-3.1
        std::vector<std::string> alpns;

        // Extension field.
        // The SCT can be sent during the TLS handshake using a TLS extension with type 
        // "signed_certificate_timestamp". Clients that support the extension SHOULD
        // send a ClientHello extension with the appropriate type and empty 
        // "extension_data".
        // https://tools.ietf.org/html/rfc6962#section-3.3.1
        bool is_support_scts;

        // Extension field.
        // The "supported_versions" extension is used by the client to indicate which
        // versions of TLS it supports and by the server to indicate which version it 
        // is using. The extension contains a list of supported versions in preference
        // order, with the most preferred version first. Implementations of this 
        // specification MUST send this extension in the ClientHello containing all
        // versions of TLS which they are prepared to negotiate
        // https://tools.ietf.org/html/rfc8446#section-4.2.1
        std::vector<version_type> supported_versions;

        // Extension field.
        // Cookies serve two primary purposes:
        // - Allowing server to force the client to demonstrate reachability at their
        // apparent network address (thus providing a measure of DoS protection). This
        // is primarily useful for non-connection-oriented transports (see [RFC6347] 
        // for an example of this).
        // - Allowing server to offload state to the client, thus allowing it to send
        // a HelloRetryRequest without storing any state. The server can do this by
        // storing the hash of the ClientHello in the HelloRetryRequest cookie
        // (protected with some suitable integrity protection algorithm).
        // https://tools.ietf.org/html/rfc8446#section-4.2.2
        std::string cookie;

        // Extension field.
        // The "key_share" extension contains the endpoint's cryptographic parameters.
        // Clients MAY send an empty client_shares vector in order to request group 
        // selection from the server, at the cost of an additional round trip.
        // https://tools.ietf.org/html/rfc8446#section-4.2.8
        std::vector<key_share> key_shares;

        // Extension field.
        // When a PSK is used and early data is allowed for that PSK, the client can
        // send Application Data in its first flight of messages. If the client opts 
        // to do so, it MUST supply both the "pre_shared_key" and "early_data" 
        // extensions.
        // https://tools.ietf.org/html/rfc8446#section-4.2.10
        bool is_support_early_data;

        // Extension field.
        // A client MUST provide a "psk_key_exchange_modes" extension if it offers a 
        // "pre_shared_key" extension. If clients offer "pre_shared_key" without a 
        // "psk_key_exchange_modes" extension, servers MUST abort the handshake.
        // Servers MUST NOT select a key exchange mode that is not listed by the
        // client. This extension also restricts the modes for use with PSK 
        // resumption. Servers SHOULD NOT send NewSessionTicket with tickets that
        // are not compatible with the advertised modes; however, if a server does
        // so, the impact will just be that the client's attempts at resumption fail.
        // https://tools.ietf.org/html/rfc8446#section-4.2.9
        std::vector<psk_mode_type> psk_modes;

        // Extension field.
        // Additional extensions.
        std::vector<extension> additional_extensions;

        // Extension field.
        // The "pre_shared_key" extension is used to negotiate the identity of the
        // pre-shared key to be used with a given handshake in association with PSK 
        // key establishment.
        // The "pre_shared_key" extension MUST be the last extension in the ClientHello
        // (this facilitates implementation as described below). Servers MUST check
        // that it is the last extension and otherwise fail the handshake with an
        // "illegal_parameter" alert.
        // https://tools.ietf.org/html/rfc8446#section-4.2.11
        std::vector<psk_identity> psk_identities;
        std::vector<std::string> psk_binders;
    };

    /*********************************************************************************
     * New client hello message.
     ********************************************************************************/
    LIB_PUMP client_hello_message* new_client_hello_message();

    /*********************************************************************************
     * Pack client hello message.
     ********************************************************************************/
    LIB_PUMP bool pack_client_hello_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack client hello message.
     ********************************************************************************/
    LIB_PUMP bool unpack_client_hello_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * The server will send this message in response to a ClientHello message to
     * proceed with the handshake if it is able to negotiate an acceptable set of
     * handshake parameters based on the ClientHello.
     * https://tools.ietf.org/html/rfc8446#section-4.1.3
     ********************************************************************************/
    struct server_hello_message {
        // In previous versions of TLS, this field was used for version negotiation 
        // and represented the selected version number for the connection. 
        // Unfortunately, some middleboxes fail when presented with new values. In 
        // TLS 1.3, the TLS server indicates its version using the "supported_versions"
        // extension (Section 4.2.1), and the legacy_version field MUST be set to
        // 0x0303, which is the version number for TLS 1.2.
        version_type legacy_version;

        // This structure is generated by the server and MUST be independently
        //  generated from the ClientHello.random.
        // https://tools.ietf.org/html/rfc5246#section-7.4.1.3
        uint8_t random[32];

        // This is the identity of the session corresponding to this connection. If 
        // the ClientHello.session_id was non-empty, the server will look in its
        // session cache for a match. If a match is found and the server is willing
        // to establish the new connection using the specified session state, the 
        // server will respond with the same value as was supplied by the client. 
        // This indicates a resumed session and dictates that the parties must
        // proceed directly to the Finished messages. Otherwise, this field will
        // contain a different value identifying the new session. The server may
        // return an empty session_id to indicate that the session will not be cached 
        // and therefore cannot be resumed. If a session is resumed, it must be 
        // resumed using the same cipher suite it was originally negotiated with.
        // Note that there is no requirement that the server resume any session even
        // if it had formerly provided a session_id. Clients MUST be prepared to do a
        // full negotiation -- including negotiating new cipher suites -- during any 
        // handshake.
        // https://tools.ietf.org/html/rfc5077
        // https://tools.ietf.org/html/rfc5246#section-7.4.1.3
        // https://tools.ietf.org/html/rfc8446#section-4.1.2
        std::string session_id;

        // The single cipher suite selected by the server from the list in 
        // ClientHello.cipher_suites. For resumed sessions, this field is the value 
        // from the state of the session being resumed.
        // https://tools.ietf.org/html/rfc5246#section-7.4.1.3
        cipher_suite_type cipher_suite;

        // The single compression algorithm selected by the server from the list in 
        // ClientHello compression_methods. For resumed sessions, this field is the 
        // value from the resumed session state.
        // https://tools.ietf.org/html/rfc5246#section-7.4.1.3
        // https://tools.ietf.org/html/rfc8446#section-4.1.2
        compression_method_type compression_method;

        // Extension field.
        // Servers that receive a client hello containing the "status_request"
        // extension MAY return a suitable certificate status response to the client 
        // along with their certificate. If OCSP is requested, they SHOULD use the 
        // information contained in the extension when selecting an OCSP responder 
        // and SHOULD include request_extensions in the OCSP request.
        // https://tools.ietf.org/html/rfc4366#section-3.6
        bool is_support_ocsp_stapling;

        // Extension field.
        // Three point formats are included in the definition of ECPointFormat above.
        // The uncompressed point format is the default format in that implementations
        // of this document MUST support it for all of their supported curves.
        // https://tools.ietf.org/html/rfc4492#section-5.1.2
        std::vector<point_format_type> supported_point_formats;

        // Extension field.
        // The server uses a zero-length SessionTicket extension to indicate to the 
        // client that it will send a new session ticket using the NewSessionTicket 
        // handshake message. The server MUST send this extension in the ServerHello 
        // if it wishes to issue a new ticket to the client using the NewSessionTicket 
        // handshake message. The server MUST NOT send this extension if it does not
        // receive one in the ClientHello. If the server fails to verify the ticket, 
        // then it falls back to performing a full handshake. If the ticket is 
        // accepted by the server but the handshake fails, the client SHOULD delete 
        // the ticket.
        // https://tools.ietf.org/html/rfc5077#section-3.2
        bool is_support_session_ticket;

        // Extension field.
        // A new TLS extension, "renegotiation_info", which contains a cryptographic 
        // binding to the enclosing TLS connection (if any) for which the renegotiation 
        // is being performed.
        // https://tools.ietf.org/html/rfc5746#section-3.2
        bool is_support_renegotiation_info;
        std::string renegotiation_info;

        // Extension field.
        // Servers that receive a ClientHello containing the
        // "application_layer_proto_negotiation" extension MAY return a suitable 
        // proto selection response to the client. The server will ignore any 
        // proto name that it does not recognize. A new ServerHello extension type.
        // https://tools.ietf.org/html/rfc7301#section-3.1
        std::string alpn;

        // Extension field.
        // The SCT can be sent during the TLS handshake using a TLS extension with type 
        // "signed_certificate_timestamp". Servers MUST only send SCTs to clients who
        // have indicated support for the extension in the ClientHello.
        // https://tools.ietf.org/html/rfc6962#section-3.3.1
        std::vector<std::string> scts;

        // Extension field.
        // A server which negotiates a version of TLS prior to TLS 1.3 MUST set
        // ServerHello.version and MUST NOT send the "supported_versions" extension. A 
        // server which negotiates TLS 1.3 MUST respond by sending a "supported_versions" 
        // extension containing the selected version value (0x0304). It MUST set the 
        // ServerHello.legacy_version field to 0x0303 (TLS 1.2).
        // https://tools.ietf.org/html/rfc8446#section-4.2.1
        version_type supported_version;

        // Extension field.
        // If using (EC)DHE key establishment, servers offer exactly one KeyShareEntry in 
        // the ServerHello. This value MUST be in the same group as the KeyShareEntry 
        // value offered by the client that the server has selected for the negotiated 
        // key exchange. Servers MUST NOT send a KeyShareEntry for any group not indicated 
        // in the client's "supported_groups" extension and MUST NOT send a KeyShareEntry 
        // when using the "psk_ke" PskKeyExchangeMode. If using (EC)DHE key establishment 
        // and a HelloRetryRequest containing a "key_share" extension was received by the 
        // client, the client MUST verify that the selected NamedGroup in the ServerHello 
        // is the same as that in the HelloRetryRequest. If this check fails, the client 
        // MUST abort the handshake with an "illegal_parameter" alert.
        // https://tools.ietf.org/html/rfc8446#section-4.2.8
        bool has_selected_key_share;
        key_share selected_key_share;

        // Extension field.
        // Upon receipt of this extension in a HelloRetryRequest, the client MUST verify 
        // that (1) the selected_group field corresponds to a group which was provided in  
        // the "supported_groups" extension in the original ClientHello and (2) the
        // selected_group field does not correspond to a group which was provided in the 
        // "key_share" extension in the original ClientHello. If either of these checks 
        // fails, then the client MUST abort the handshake with an "illegal_parameter"
        // alert. Otherwise, when sending the new ClientHello, the client MUST replace the 
        // original "key_share" extension with one containing only a new KeyShareEntry for 
        // the group indicated in the selected_group field of the triggering 
        // HelloRetryRequest.
        // https://tools.ietf.org/html/rfc8446#section-4.2.8
        ssl::curve_group_type selected_group;

        // Extension field.
        // Prior to accepting PSK key establishment, the server MUST validate 
        // the corresponding binder value. If this value is not present or does not
        // validate, the server MUST abort the handshake. 
        // Servers SHOULD NOT attempt to validate multiple binders; rather, they SHOULD
        // select a single PSK and validate solely the binder that corresponds to that 
        // PSK. See Section 8.2 and Appendix E.6 for the security rationale for this
        // requirement. In order to accept PSK key establishment, the server sends a 
        // "pre_shared_key" extension indicating the selected identity.
        // https://tools.ietf.org/html/rfc8446#section-4.2.11
        bool has_selected_psk_identity;
        uint16_t selected_psk_identity;

        // Extension field.
        // When a server is operating statelessly, it may receive an unprotected
        // record of type change_cipher_spec between the first and second ClientHello. 
        // Since the server is not storing any state, this will appear as if it were
        // the first message to be received. Servers operating statelessly MUST ignore 
        // these records.
        // https://tools.ietf.org/html/rfc8446#section-4.2.2
        std::string cookie;
    };

    /*********************************************************************************
     * New server hello message.
     ********************************************************************************/
    LIB_PUMP server_hello_message* new_server_hello_message();

    /*********************************************************************************
     * Pack server hello message.
     ********************************************************************************/
    LIB_PUMP bool pack_server_hello_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack server hello message.
     ********************************************************************************/
    LIB_PUMP bool unpack_server_hello_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * This message is sent by the server during the TLS handshake before the
     * ChangeCipherSpec message. This message MUST be sent if the server included a 
     * SessionTicket extension in the ServerHello. This message MUST NOT be sent if 
     * the server did not include a SessionTicket extension in the ServerHello. This 
     * message is included in the hash used to create and verify the Finished message.
     * In the case of a full handshake, the server MUST verify the client's Finished 
     * message before sending the ticket. The client MUST NOT treat the ticket as 
     * valid until it has verified the server's Finished message. If the server 
     * determines that it does not want to include a ticket after it has included the 
     * SessionTicket extension in the ServerHello , then it sends a zero-length ticket 
     * in the NewSessionTicket handshake message.
     * https://tools.ietf.org/html/rfc5077#section-3.3
     ********************************************************************************/
    struct new_session_ticket_message {
        uint32_t lifetime_hint;
        std::string ticket;
    };

    /*********************************************************************************
     * New new session message.
     ********************************************************************************/
    LIB_PUMP new_session_ticket_message* new_new_session_ticket_message();

    /*********************************************************************************
     * Pack new session message.
     ********************************************************************************/
    LIB_PUMP bool pack_new_session_ticket_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack new session message.
     ********************************************************************************/
    LIB_PUMP bool unpack_new_session_ticket_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * At any time after the server has received the client Finished message, it MAY 
     * send a NewSessionTicket message. This message creates a unique association 
     * between the ticket value and a secret PSK derived from the resumption master
     * secret.
     * https://tools.ietf.org/html/rfc8446#section-4.6.1
     ********************************************************************************/
    struct new_session_ticket_tls13_message {
        // Indicates the lifetime in seconds as a 32-bit unsigned integer in network 
        // byte order from the time of ticket issuance. Servers MUST NOT use any value 
        // greater than 604800 seconds (7 days). The value of zero indicates that the 
        // ticket should be discarded immediately. Clients MUST NOT cache tickets for 
        // longer than 7 days, regardless of the ticket_lifetime, and MAY delete 
        // tickets valid earlier based on local policy.  A server MAY treat a ticket
        // as for a shorter period of time than what is stated in the ticket_lifetime.
        // https://tools.ietf.org/html/rfc8446#section-4.6.1
        uint32_t lifetime;

        // A securely generated, random 32-bit value that is used to obscure the age 
        // of the ticket that the client includes in the added to this "pre_shared_key" 
        // extension. The client-side ticket age is value modulo 2^32 to obtain the 
        // value that is transmitted by the client. The server MUST generate a fresh
        // value for each ticket it sends.
        // https://tools.ietf.org/html/rfc8446#section-4.6.1
        uint32_t age_add;

        // A per-ticket value that is unique across all tickets issued on this
        // connection.
        // https://tools.ietf.org/html/rfc8446#section-4.6.1
        std::string nonce;

        // The value of the ticket to be used as the PSK identity. The ticket itself 
        // is an opaque label. It MAY be either a database lookup key or a  
        // self-encrypted and self-authenticated value.
        // https://tools.ietf.org/html/rfc8446#section-4.6.1
        std::string label;

        // A set of extension values for the ticket. The "Extension" format is defined 
        // in Section 4.2. Clients MUST ignore unrecognized extensions. The sole 
        // extension currently defined for NewSessionTicket is "early_data", indicating 
        // that the ticket may be used to send 0-RTT data (Section 4.2.10). It contains 
        // the following value "max_early_data_size".
        // https://tools.ietf.org/html/rfc8446#section-4.6.1
        uint32_t max_early_data_size;
    };

    /*********************************************************************************
     * New new session ticket message.
     ********************************************************************************/
    LIB_PUMP new_session_ticket_tls13_message* new_new_session_ticket_tls13_message();

    /*********************************************************************************
     * Pack new session ticket message.
     ********************************************************************************/
    LIB_PUMP bool pack_new_session_ticket_tls13_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack new session ticket message.
     ********************************************************************************/
    LIB_PUMP bool unpack_new_session_ticket_tls13_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * If the server sent an "early_data" extension in EncryptedExtensions, the client 
     * MUST send an EndOfEarlyData message after receiving the server Finished. If the 
     * server does not send an "early_data" extension in EncryptedExtensions, then the 
     * client MUST NOT send an EndOfEarlyData message. This message indicates that all 
     * 0-RTT application_data messages, if any, have been transmitted and that the
     * following records are protected under handshake traffic keys. Servers MUST NOT 
     * send this message, and clients receiving it MUST terminate the connection with 
     * an "unexpected_message" alert. This message is encrypted under keys derived
     * from the client_early_traffic_secret.
     * https://tools.ietf.org/html/rfc8446#section-4.5
     ********************************************************************************/
    struct end_early_data_message {
    };

    /*********************************************************************************
     * New end early data message.
     ********************************************************************************/
    LIB_PUMP end_early_data_message* new_end_early_data_message();

    /*********************************************************************************
     * Pack end early data message.
     ********************************************************************************/
    LIB_PUMP bool pack_end_early_data_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack end early data message.
     ********************************************************************************/
    LIB_PUMP bool unpack_end_early_data_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * In all handshakes, the server MUST send the EncryptedExtensions message  
     * immediately after the ServerHello message. This is the first message that is
     * encrypted under keys derived from the server_handshake_traffic_secret.
     * The EncryptedExtensions message contains extensions that can be protected, any 
     * which are not needed to establish the cryptographic context but which are not 
     * associated with individual certificates. The client MUST check
     * EncryptedExtensions for the presence of any forbidden extensions and if any are
     * found MUST abort the handshake with an "illegal_parameter" alert.
     ********************************************************************************/
    // https://tools.ietf.org/html/rfc8446#section-4.3.1
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

    /*********************************************************************************
     * New encrypted extensions message.
     ********************************************************************************/
    LIB_PUMP encrypted_extensions_message* new_encrypted_extensions_message();

    /*********************************************************************************
     * Pack encrypted extensions message.
     ********************************************************************************/
    LIB_PUMP bool pack_encrypted_extensions_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack encrypted extensions message.
     ********************************************************************************/
    LIB_PUMP bool unpack_encrypted_extensions_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * This message conveys the endpoint's certificate chain to the peer. The server 
     * MUST send a Certificate message whenever the agreed-upon key exchange method 
     * uses certificates for authentication (this includes all key exchange methods 
     * defined in this document except PSK).
     * The client MUST send a Certificate message if and only if the server has 
     * requested client authentication via a CertificateRequest message. If the server 
     * requests client authentication but no suitable certificate is available, the 
     * client MUST send a Certificate message containing no certificates (i.e., with 
     * the "certificate_list" field having length 0). A Finished message MUST be sent 
     * regardless of whether the Certificate message is empty.
     ********************************************************************************/
    struct certificate_message {
        // A sequence of Certificates, each containing a single certificate and set
        // of extensions.
        // https://tools.ietf.org/html/rfc8446#section-4.4.2
        std::vector<std::string> certificates;
    };

    struct certificate_tls13_message {
        // A sequence of Certificates, each containing a single certificate and set
        // of extensions.
        // https://tools.ietf.org/html/rfc8446#section-4.4.2
        std::vector<std::string> certificates;

        // Extension field.
        // https://tools.ietf.org/html/rfc8446#section-4.4.2.1
        bool is_support_ocsp_stapling;
        std::string ocsp_staple;

        // Extension field.
        // Extensions in the Certificate message from the client MUST correspond to
        // extensions in the CertificateRequest message from the server.
        // https://tools.ietf.org/html/rfc8446#section-4.4.2.1
        // https://tools.ietf.org/html/rfc8446#section-4.3.2
        bool is_support_scts;
        std::vector<std::string> scts;
    };

    /*********************************************************************************
     * New certificate message.
     ********************************************************************************/
    LIB_PUMP certificate_message* new_certificate_message();

    /*********************************************************************************
     * Pack certificate message.
     ********************************************************************************/
    LIB_PUMP bool pack_certificate_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack certificate message.
     ********************************************************************************/
    LIB_PUMP bool unpack_certificate_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * New certificate tls13 message.
     ********************************************************************************/
    LIB_PUMP certificate_tls13_message* new_certificate_tls13_message();

    /*********************************************************************************
     * Pack certificate tls13 message.
     ********************************************************************************/
    LIB_PUMP bool pack_certificate_tls13_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack certificate tls13 message.
     ********************************************************************************/
    LIB_PUMP bool unpack_certificate_tls13_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * This message will be sent immediately after the server certificate
     * message (or the server hello message, if this is an anonymous
     * negotiation).
     * The server key exchange message is sent by the server only when
     * the server certificate message (if sent) does not contain enough
     * data to allow the client to exchange a premaster secret.
     * https://tools.ietf.org/html/rfc4346#section-7.4.3
     ********************************************************************************/
    struct server_key_exchange_message {
        std::string key;
    };

    /*********************************************************************************
     * New server key exchange message.
     ********************************************************************************/
    LIB_PUMP server_key_exchange_message* new_server_key_exchange_message();

    /*********************************************************************************
     * Pack server key exchange message.
     ********************************************************************************/
    LIB_PUMP bool pack_server_key_exchange_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack server key exchange message.
     ********************************************************************************/
    LIB_PUMP bool unpack_server_key_exchange_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * When this message will be sent:
     * A non-anonymous server can optionally request a certificate from the client, 
     * if it is appropriate for the selected cipher suite. This message, if sent, will 
     * immediately follow the Server Key Exchange message (if it is sent; otherwise, 
     * the Server Certificate message).
     * https://tools.ietf.org/html/rfc4346#section-7.4.4
     ********************************************************************************/
    struct certificate_req_message {
        // This field is a list of the types of certificates requested, sorted in 
        // order of the server's preference.
        std::vector<uint8_t> certificate_types;

        // https://tools.ietf.org/html/rfc8446#section-4.3.2
        // https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
        bool has_signature_algorithms;
        std::vector<ssl::signature_scheme> supported_signature_algorithms;

        // A list of the distinguished names of acceptable certificate authorities.
        // These distinguished names may specify a desired distinguished name for a 
        // root CA or for a subordinate CA; thus, this message can be used to describe 
        // both known roots and a desired authorization space. If the 
        // certificate_authorities list is empty then the client MAY send any 
        // certificate of the appropriate ClientCertificateType, unless there is some
        // external arrangement to the contrary.
        // https://tools.ietf.org/html/rfc4346#section-7.4.4
        std::vector<std::string> certificate_authorities;
    };

    /*********************************************************************************
     * New certificate request message.
     ********************************************************************************/
    LIB_PUMP certificate_req_message* new_certificate_req_message();

    /*********************************************************************************
     * Pack certificate request message.
     ********************************************************************************/
    LIB_PUMP bool pack_certificate_req_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack certificate request message.
     ********************************************************************************/
    LIB_PUMP bool unpack_certificate_req_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * A server which is authenticating with a certificate MAY optionally request a 
     * certificate from the client. This message, if sent, MUST follow
     * EncryptedExtensions.
     * https://tools.ietf.org/html/rfc8446#section-4.3.2
     ********************************************************************************/
    struct certificate_req_tls13_message {
        // Extension field.
        // https://tools.ietf.org/html/rfc8446#section-4.3.2
        // https://tools.ietf.org/html/rfc4366#section-3.6
        bool is_support_ocsp_stapling;

        // Extension field.
        // Extensions in the Certificate message from the client MUST correspond to
        // extensions in the CertificateRequest message from the server.
        // https://tools.ietf.org/html/rfc8446#section-4.3.2
        // https://tools.ietf.org/html/rfc8446#section-4.4.2.1
        bool is_support_scts;

        // Extension field.
        // https://tools.ietf.org/html/rfc8446#section-4.3.2
        // https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
        // https://tools.ietf.org/html/rfc8446#section-4.2.3
        std::vector<ssl::signature_scheme> supported_signature_schemes;

        // Extension field.
        // https://tools.ietf.org/html/rfc8446#section-4.3.2
        // https://tools.ietf.org/html/rfc8446#section-4.2.3
        std::vector<ssl::signature_scheme> supported_signature_algorithms_certs;

        // Extension field.
        // https://tools.ietf.org/html/rfc8446#section-4.3.2
        std::vector<std::string> certificate_authorities;
    };

    /*********************************************************************************
     * New certificate request tls13 message.
     ********************************************************************************/
    LIB_PUMP certificate_req_tls13_message* new_certificate_req_tls13_message();

    /*********************************************************************************
     * Pack certificate request tls13 message.
     ********************************************************************************/
    LIB_PUMP bool pack_certificate_req_tls13_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack certificate request tls13 message.
     ********************************************************************************/
    LIB_PUMP bool unpack_certificate_req_tls13_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * The server hello done message is sent by the server to indicate the end of the
     * server hello and associated messages. After sending this message, the server 
     * will wait for a client response. This message means that the server is done 
     * sending messages to support the key exchange, and the client can proceed with 
     * its phase of the key exchange. Upon receipt of the server hello done message, 
     * the client SHOULD verify that the server provided a valid certificate, if 
     * required and check that the server hello parameters are acceptable.
     * https://tools.ietf.org/html/rfc4346#section-7.4.5
     ********************************************************************************/
    struct server_hello_done_message {
    };

    /*********************************************************************************
     * New server hello done message.
     ********************************************************************************/
    LIB_PUMP server_hello_done_message* new_server_hello_done_message();

    /*********************************************************************************
     * Pack server hello done message.
     ********************************************************************************/
    LIB_PUMP bool pack_server_hello_done_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack server hello done message.
     ********************************************************************************/
    LIB_PUMP bool unpack_server_hello_done_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * This message is used to provide explicit verification of a client certificate. 
     * This message is only sent following a client certificate that has signing
     * capability (i.e., all certificates except those containing fixed Diffie-Hellman
     * parameters). When sent, it MUST immediately follow the client key exchange 
     * message.
     * https://tools.ietf.org/html/rfc4346#section-7.4.8
     ********************************************************************************/
    struct certificate_verify_message {
        bool has_signature_scheme;
        ssl::signature_scheme signature_scheme;
        std::string signature;
    };

    /*********************************************************************************
     * New certificate verify message.
     ********************************************************************************/
    LIB_PUMP certificate_verify_message* new_certificate_verify_message();

    /*********************************************************************************
     * Pack certificate verify message.
     ********************************************************************************/
    LIB_PUMP bool pack_certificate_verify_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack certificate verify message.
     ********************************************************************************/
    LIB_PUMP bool unpack_certificate_verify_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * This message is always sent by the client. It MUST immediately follow the 
     * client certificate message, if it is sent. Otherwise it MUST be the first 
     * message sent by the client after it receives the server hello done message.
     * With this message, the premaster secret is set, either though direct
     * transmission of the RSA-encrypted secret or by the transmission of 
     * Diffie-Hellman parameters that will allow each side to agree upon the same
     * premaster secret. When the key exchange method is DH_RSA or DH_DSS, client 
     * certification has been requested, and the client was able to respond with a 
     * certificate that contained a Diffie-Hellman public key whose parameters (group
     * and generator) matched those specified by the server in its certificate, this
     * message MUST not contain any data.
     * https://tools.ietf.org/html/rfc4346#section-7.4.7
     ********************************************************************************/
    struct client_key_exchange_message {
        std::string ciphertext;
    };

    /*********************************************************************************
     * New client key exchange message.
     ********************************************************************************/
    LIB_PUMP client_key_exchange_message* new_client_key_exchange_message();

    /*********************************************************************************
     * Pack client key exchange message.
     ********************************************************************************/
    LIB_PUMP bool pack_client_key_exchange_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack client key exchange message.
     ********************************************************************************/
    LIB_PUMP bool unpack_client_key_exchange_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * A finished message is always sent immediately after a change cipher spec 
     * message to verify that the key exchange and authentication processes were
     * successful. It is essential that a change cipher spec message be received
     * between the other handshake messages and the Finished message.
     * The finished message is the first protected with the just-negotiated algorithms,
     * keys, and secrets. Recipients of finished messages MUST verify that the 
     * contents are correct. Once a side has sent its Finished message and received
     * and validated the Finished message from its peer, it may begin to send and 
     * receive application data over the connection.
     * https://tools.ietf.org/html/rfc4346#section-7.4.9
     ********************************************************************************/
    struct finished_message {
        std::string verify_data;
    };

    /*********************************************************************************
     * New finished message.
     ********************************************************************************/
    LIB_PUMP finished_message* new_finished_message();

    /*********************************************************************************
     * Pack finished message.
     ********************************************************************************/
    LIB_PUMP bool pack_finished_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack finished message.
     ********************************************************************************/
    LIB_PUMP bool unpack_finished_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * Servers that receive a client hello containing the "status_request" extension
     * MAY return a suitable certificate status response to the client along with 
     * their certificate. If OCSP is requested, they SHOULD use the information
     * contained in the extension when selecting an OCSP responder and SHOULD include 
     * request_extensions in the OCSP request.
     * Servers return a certificate response along with their certificate by sending a 
     * "CertificateStatus" message immediately after the "Certificate" message (and 
     * before any "ServerKeyExchange" or "CertificateRequest" messages). If a server 
     * returns a "CertificateStatus" message, then the server MUST have included an
     * extension of type "status_request" with empty "extension_data" in the extended
     * server hello.
     * https://tools.ietf.org/html/rfc4366#section-3.6
     ********************************************************************************/
    struct certificate_status_message {
        std::string response;
    };

    /*********************************************************************************
     * New certificate status message.
     ********************************************************************************/
    LIB_PUMP certificate_status_message* new_certificate_status_message();

    /*********************************************************************************
     * Pack certificate status message.
     ********************************************************************************/
    LIB_PUMP bool pack_certificate_status_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack certificate status message.
     ********************************************************************************/
    LIB_PUMP bool unpack_certificate_status_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * The KeyUpdate handshake message is used to indicate that the sender is updating 
     * its sending cryptographic keys. This message can be sent by either peer after 
     * it has sent a Finished message. Implementations  that receive a KeyUpdate 
     * message prior to receiving a Finished message MUST terminate the connection
     * with an "unexpected_message" alert. After sending a KeyUpdate message, the
     * sender SHALL send all its traffic using the next generation of keys, computed
     * as described in Section 7.2. Upon receiving a KeyUpdate, the receiver MUST
     * update its receiving keys.
     * https://tools.ietf.org/html/rfc8446#section-4.6.3
     ********************************************************************************/
    struct key_update_message {
        // Indicates whether the recipient of the KeyUpdate should respond with its
        // own KeyUpdate. If an implementation receives any other value, it MUST
        // terminate the connection with an "illegal_parameter" alert.
        bool update_requested;
    };

    /*********************************************************************************
     * New key update message.
     ********************************************************************************/
    LIB_PUMP key_update_message* new_key_update_message();

    /*********************************************************************************
     * Pack key update message.
     ********************************************************************************/
    LIB_PUMP bool pack_key_update_message(void *msg, io_buffer *iob);

    /*********************************************************************************
     * Unpack key update message.
     ********************************************************************************/
    LIB_PUMP bool unpack_key_update_message(io_buffer *iob, void *msg);

    /*********************************************************************************
     * Pack message hash message.
     ********************************************************************************/
    LIB_PUMP io_buffer* pack_msg_hash_message(const std::string &hash);

} // namespace tls
} // namespace quic
} // namespace proto
} // namespace pump

#endif
