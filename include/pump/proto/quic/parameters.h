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

#ifndef pump_proto_quic_parameters_h
#define pump_proto_quic_parameters_h

#include "pump/proto/quic/cid.h"
#include "pump/proto/quic/types.h"
#include "pump/proto/quic/tls/types.h"

#include "pump/transport/address.h"

namespace pump {
namespace proto {
namespace quic {

using transport::address;

typedef uint64_t transport_parameter_type;

/*********************************************************************************
 * This parameter is the value of the Destination Connection ID field from the
 * first Initial packet sent by the client. This transport parameter is only sent
 * by a server.
 ********************************************************************************/
const static transport_parameter_type PARAM_ORIGINAL_DESTINATION_CONNECTION_ID = 0x00;

/*********************************************************************************
 * The maximum idle timeout is a value in milliseconds that is encoded as an
 * integer. Idle timeout is disabled when both endpoints omit this transport
 * parameter or specify a value of 0.
 ********************************************************************************/
const static transport_parameter_type PARAM_MAX_IDLE_TIMEOUT = 0x01;

/*********************************************************************************
 * A stateless reset token is used in verifying a stateless reset. This parameter
 * is a sequence of 16 bytes. This transport parameter MUST NOT be sent by a
 * client but MAY be sent by a server. A server that does not send this transport
 * parameter cannot use stateless reset (Section 10.3) for the connection ID
 * negotiated during the handshake.
 ********************************************************************************/
const static transport_parameter_type PARAM_STATELESS_RESET_TOKEN = 0x02;

/*********************************************************************************
 * he maximum UDP payload size parameter is an integer value that limits the size
 * of UDP payloads that the endpoint is willing to receive. UDP datagrams with
 * payloads larger than this limit are not likely to be processed by the receiver.
 *
 * The default for this parameter is the maximum permitted UDP payload of 65527.
 * Values below 1200 are invalid.
 *
 * This limit does act as an additional constraint on datagram size in the same
 * way as the path MTU, but it is a property of the endpoint and not the path;
 * see Section 14. It is expected that this is the space an endpoint dedicates
 * to holding incoming packets.
 ********************************************************************************/
const static transport_parameter_type PARAM_MAX_UDP_PAYLOAD_SIZE = 0x03;

/*********************************************************************************
 * The initial maximum data parameter is an integer value that contains the
 * initial value for the maximum amount of data that can be sent on the
 *connection. This is equivalent to sending a MAX_DATA for the connection
 *immediately after completing the handshake.
 ********************************************************************************/
const static transport_parameter_type PARAM_INITIAL_MAX_DATA = 0x04;

/*********************************************************************************
 * This parameter is an integer value specifying the initial flow control limit
 * for locally initiated bidirectional streams. This limit applies to newly
 * created bidirectional streams opened by the endpoint that sends the transport
 * parameter. In client transport parameters, this applies to streams with an
 * identifier with the least significant two bits set to 0x00; in server
 * transport parameters, this applies to streams with the least significant two
 * bits set to 0x01.
 ********************************************************************************/
const static transport_parameter_type PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05;

/*********************************************************************************
 * This parameter is an integer value specifying the initial flow control limit
 * for peer-initiated bidirectional streams. This limit applies to newly created
 * bidirectional streams opened by the endpoint that receives the transport
 * parameter. In client transport parameters, this applies to streams with an
 * identifier with the least significant two bits set to 0x01; in server
 * transport parameters, this applies to streams with the least significant two
 * bits set to 0x00.
 ********************************************************************************/
const static transport_parameter_type PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06;

/*********************************************************************************
 * This parameter is an integer value specifying the initial flow control limit
 * for unidirectional streams. This limit applies to newly created unidirectional
 * streams opened by the endpoint that receives the transport parameter. In client
 * transport parameters, this applies to streams with an identifier with the
 * least significant two bits set to 0x03; in server transport parameters, this
 * applies to streams with the least significant two bits set to 0x02.
 ********************************************************************************/
const static transport_parameter_type PARAM_INITIAL_MAX_STREAM_DATA_UNI = 0x07;

/*********************************************************************************
 * The initial maximum bidirectional streams parameter is an integer value that
 * contains the initial maximum number of bidirectional streams the endpoint that
 * receives this transport parameter is permitted to initiate. If this parameter
 * is absent or zero, the peer cannot open bidirectional streams until a
 * MAX_STREAMS frame is sent. Setting this parameter is equivalent to sending a
 * MAX_STREAMS of the corresponding type with the same value.
 ********************************************************************************/
const static transport_parameter_type PARAM_INITIAL_MAX_STREAMS_BIDI = 0x08;

/*********************************************************************************
 * The initial maximum unidirectional streams parameter is an integer value that
 * contains the initial maximum number of unidirectional streams the endpoint
 * that receives this transport parameter is permitted to initiate. If this
 * parameter is absent or zero, the peer cannot open unidirectional streams until
 * a MAX_STREAMS frame is sent. Setting this parameter is equivalent to sending a
 * MAX_STREAMS of the corresponding type with the same value.
 ********************************************************************************/
const static transport_parameter_type PARAM_INITIAL_MAX_STREAMS_UNI = 0x09;

/*********************************************************************************
 * The acknowledgment delay exponent is an integer value indicating an exponent
 * used to decode the ACK Delay field in the ACK frame. If this value is absent,
 * a default value of 3 is assumed (indicating a multiplier of 8). Values above
 * 20 are invalid.
 ********************************************************************************/
const static transport_parameter_type PARAM_ACK_DELAY_EXPONENT = 0x0a;

/*********************************************************************************
 * The maximum acknowledgment delay is an integer value indicating the maximum
 * amount of time in milliseconds by which the endpoint will delay sending
 * acknowledgments. This value SHOULD include the receiver's expected delays in
 * alarms firing. For example, if a receiver sets a timer for 5ms and alarms
 * commonly fire up to 1ms late, then it should send a max_ack_delay of 6ms. If
 * this value is absent, a default of 25 milliseconds is assumed. Values of 214
 * or greater are invalid.
 ********************************************************************************/
const static transport_parameter_type PARAM_MAX_ACK_DELAY = 0x0b;

/*********************************************************************************
 * The disable active migration transport parameter is included if the endpoint
 * does not support active connection migration (Section 9) on the address being
 * used during the handshake. An endpoint that receives this transport parameter
 * MUST NOT use a new local address when sending to the address that the peer
 * used during the handshake. This transport parameter does not prohibit
 * connection migration after a client has acted on a preferred_address transport
 * parameter. This parameter is a zero-length value.
 ********************************************************************************/
const static transport_parameter_type PARAM_DISABLE_ACTIVE_MIGRATION = 0x0c;

/*********************************************************************************
 * The server's preferred address is used to effect a change in server address at
 * the end of the handshake. This transport parameter is only sent by a server.
 * Servers MAY choose to only send a preferred address of one address family by
 * sending an all-zero address and port (0.0.0.0:0 or [::]:0) for the other
 *family. IP addresses are encoded in network byte order.
 *
 * The preferred_address transport parameter contains an address and port for both
 * IPv4 and IPv6. The four-byte IPv4 Address field is followed by the associated
 * two-byte IPv4 Port field. This is followed by a 16-byte IPv6 Address field and
 * two-byte IPv6 Port field. After address and port pairs, a Connection ID Length
 * field describes the length of the following Connection ID field. Finally, a
 * 16-byte Stateless Reset Token field includes the stateless reset token
 * associated with the connection ID.
 *
 * The Connection ID field and the Stateless Reset Token field contain an
 * alternative connection ID that has a sequence number of 1. Having these values
 * sent alongside the preferred address ensures that there will be at least one
 * unused active connection ID when the client initiates migration to the
 * preferred address.
 *
 * The Connection ID and Stateless Reset Token fields of a preferred address are
 * identical in syntax and semantics to the corresponding fields of a
 * NEW_CONNECTION_ID frame. A server that chooses a zero-length connection ID
 * MUST NOT provide a preferred address. Similarly, a server MUST NOT include a
 * zero-length connection ID in this transport parameter. A client MUST treat a
 * violation of these requirements as a connection error of type
 * TRANSPORT_PARAMETER_ERROR.
 *
 * Preferred Address {
 *   IPv4 Address (32),
 *   IPv4 Port (16),
 *   IPv6 Address (128),
 *   IPv6 Port (16),
 *   Connection ID Length (8),
 *   Connection ID (..),
 *   Stateless Reset Token (128),
 * }
 ********************************************************************************/
const static transport_parameter_type PARAM_PREFERRED_ADDRESS = 0x0d;

/*********************************************************************************
 * This is an integer value specifying the maximum number of connection IDs from
 * the peer that an endpoint is willing to store. This value includes the
 * connection ID received during the handshake, that received in the
 * preferred_address transport parameter, and those received in NEW_CONNECTION_ID
 * frames. The value of the active_connection_id_limit parameter MUST be at least
 * 2. An endpoint that receives a value less than 2 MUST close the connection
 * with an error of type TRANSPORT_PARAMETER_ERROR. If this transport parameter
 * is absent, a default of 2 is assumed. If an endpoint issues a zero-length
 * connection ID, it will never send a NEW_CONNECTION_ID frame and therefore
 * ignores the active_connection_id_limit value received from its peer.
 ********************************************************************************/
const static transport_parameter_type PARAM_ACTIVE_CONNECTION_ID_LIMIT = 0x0e;

/*********************************************************************************
 * This is the value that the endpoint included in the Source Connection ID field
 * of the first Initial packet it sends for the connection.
 ********************************************************************************/
const static transport_parameter_type PARAM_INITIAL_SOURCE_CONNECTION_ID = 0x0f;

/*********************************************************************************
 * This is the value that the server included in the Source Connection ID field of
 * a Retry packet. This transport parameter is only sent by a server.
 ********************************************************************************/
const static transport_parameter_type PARAM_RETRY_SOURCE_CONNECTION_ID = 0x10;

/*********************************************************************************
 * The max_datagram_frame_size transport parameter is aninteger value (represented
 * as a variable-length integer) that represents the maximum size of a DATAGRAM
 * frame (including the frame type, length, and payload) the endpoint is willing
 * to receive, in bytes.  An endpoint that includes this parameter supports the
 * DATAGRAM frame types and is willing to receive such frames on this connection.
 ********************************************************************************/
const static transport_parameter_type PARAM_MAX_DATAGRAM_FRAME_SIZE = 0x20;

/*********************************************************************************
 * Transport preferred address
 ********************************************************************************/
struct transport_preferred_address {
    address ipv4;
    address ipv6;
    cid id;
    std::string stateless_reset_token;
};

/*********************************************************************************
 * Transport parameters
 ********************************************************************************/
struct transport_parameters {
    cid original_destination_cid;

    int64_t max_idle_timeout;

    std::string stateless_reset_token;

    int64_t max_udp_payload_size;

    int64_t initial_max_data;

    int64_t initial_max_stream_data_bidi_local;

    int64_t initial_max_stream_data_bidi_remote;

    int64_t initial_max_stream_data_uni;

    int64_t max_streams_bidi;

    int64_t max_streams_uni;

    int64_t max_ack_delay;

    int8_t ack_delay_exponent;

    bool disable_active_migration;

    transport_preferred_address *preferred_address;

    int64_t active_connection_id_limit;

    cid initial_source_connection_id;

    cid retry_source_connection_id;

    int32_t max_datagram_frame_size;
};

/*********************************************************************************
 * Pack transport parameters
 ********************************************************************************/
bool pack_parameters(stream_initiator_type initiator,
                     const transport_parameters *params,
                     io_buffer *iob);

/*********************************************************************************
 * Unpack transport parameters
 ********************************************************************************/
bool unpack_parameters(stream_initiator_type initiator,
                       io_buffer *iob,
                       transport_parameters *params);

/*********************************************************************************
 * Get transport parameters extension type
 ********************************************************************************/
tls::extension_type get_paramerters_extension_type(version_number version);

}  // namespace quic
}  // namespace proto
}  // namespace pump

#endif