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

#ifndef pump_proto_quic_config_h
#define pump_proto_quic_config_h

#include <vector>

#include "pump/proto/quic/types.h"

namespace pump {
namespace proto {
namespace quic {

struct config {
    // The QUIC versions that can be negotiated.
    // If not set, it uses all versions available.
    // Warning: This API should not be considered stable and will change soon.
    std::vector<version_number> versions;

    // The length of the connection ID in bytes.
    // It can be 0, or any value between 4 and 18.
    // If not set, the interpretation depends on where the Config is used:
    // If used for dialing an address, a 0 byte connection ID will be used.
    // If used for a server, or dialing on a packet conn, a 4 byte connection ID
    // will be used. When dialing on a packet conn, the ConnectionIDLength value
    // must be the same for every Dial call.
    int32_t connection_id_length;

    // HandshakeIdleTimeout is the idle timeout before completion of the
    // handshake. Specifically, if we don't receive any packet from the peer
    // within this time, the connection attempt is aborted. If this value is zero,
    // the timeout is set to 5 seconds.
    int64_t handshake_idle_timeout;

    // MaxIdleTimeout is the maximum duration that may pass without any incoming
    // network activity. The actual value for the idle timeout is the minimum of
    // this value and the peer's. This value only applies after the handshake has
    // completed. If the timeout is exceeded, the connection is closed. If this
    // value is zero, the timeout is set to 30 seconds.
    int64_t max_idle_timeout;

    // AcceptToken determines if a Token is accepted.
    // It is called with token = nil if the client didn't send a token.
    // If not set, a default verification function is used:
    // * it verifies that the address matches, and
    //   * if the token is a retry token, that it was issued within the last 5
    //   seconds
    //   * else, that it was issued within the last 24 hours.
    // This option is only valid for the server.
    // AcceptToken func(clientAddr net.Addr, token *Token) bool

    // The TokenStore stores tokens received from the server.
    // Tokens are used to skip address validation on future connection attempts.
    // The key used to store tokens is the ServerName from the tls.Config, if set
    // otherwise the token is associated with the server's IP address.
    // TokenStore TokenStore

    // InitialStreamReceiveWindow is the initial size of the stream-level flow
    // control window for receiving data. If the application is consuming data
    // quickly enough, the flow control auto-tuning algorithm will increase the
    // window up to MaxStreamReceiveWindow. If this value is zero, it will default
    // to 512 KB.
    int64_t initial_stream_receive_window;

    // MaxStreamReceiveWindow is the maximum stream-level flow control window for
    // receiving data. If this value is zero, it will default to 6 MB.
    int64_t max_stream_receive_window;

    // InitialConnectionReceiveWindow is the initial size of the stream-level flow
    // control window for receiving data. If the application is consuming data
    // quickly enough, the flow control auto-tuning algorithm will increase the
    // window up to MaxConnectionReceiveWindow. If this value is zero, it will
    // default to 512 KB.
    int64_t initial_connection_receive_window;

    // MaxConnectionReceiveWindow is the connection-level flow control window for
    // receiving data. If this value is zero, it will default to 15 MB.
    int64_t max_connection_receive_window;

    // MaxIncomingStreams is the maximum number of concurrent bidirectional
    // streams that a peer is allowed to open. Values above 2^60 are invalid. If
    // not set, it will default to 100. If set to a negative value, it doesn't
    // allow any bidirectional streams.
    int64_t max_incoming_streams;

    // MaxIncomingUniStreams is the maximum number of concurrent unidirectional
    // streams that a peer is allowed to open. Values above 2^60 are invalid. If
    // not set, it will default to 100. If set to a negative value, it doesn't
    // allow any unidirectional streams.
    int64_t max_incoming_uni_streams;

    // The StatelessResetKey is used to generate stateless reset tokens.
    // If no key is configured, sending of stateless resets is disabled.
    std::string stateless_reset_key;

    // KeepAlive defines whether this peer will periodically send a packet to keep
    // the connection alive.
    bool keepalive;

    // DisablePathMTUDiscovery disables Path MTU Discovery (RFC 8899).
    // Packets will then be at most 1252 (IPv4) / 1232 (IPv6) bytes in size.
    // Note that Path MTU discovery is always disabled on Windows, see
    // https://github.com/lucas-clemente/quic-go/issues/3273.
    bool disable_path_mtu_discovery;

    // DisableVersionNegotiationPackets disables the sending of Version
    // Negotiation packets. This can be useful if version information is exchanged
    // out-of-band. It has no effect for a client.
    bool disable_version_negotiation_packets;

    // See https://datatracker.ietf.org/doc/draft-ietf-quic-datagram/.
    // Datagrams will only be available when both peers enable datagram support.
    bool enable_datagrams;
};

/*********************************************************************************
 * Init config with defualt paramaters
 ********************************************************************************/
void init_config(config *cfg);

/*********************************************************************************
 * Populate config and fix with defualt paramaters
 ********************************************************************************/
void populate_config(config *cfg);

}  // namespace quic
}  // namespace proto
}  // namespace pump

#endif