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

#include "pump/proto/quic/utils.h"
#include "pump/proto/quic/defaults.h"
#include "pump/proto/quic/parameters.h"

namespace pump {
namespace proto {
namespace quic {

    static bool __pack_preferred_address(
        const transport_preferred_address *preferred_address,
        io_buffer *iob) {
        auto addr_v4 = (const sockaddr_in*)preferred_address->ipv4.get();;
        if (!iob->write((block_t*)&addr_v4->sin_addr.s_addr, 4) ||
            !iob->write((block_t*)&addr_v4->sin_port, 2)) {
            return false;
        }

        auto addr_v6 = (const sockaddr_in6*)preferred_address->ipv6.get();;
        if (!iob->write((block_t*)&addr_v6->sin6_addr, 16) ||
            !iob->write((block_t*)&addr_v6->sin6_port, 2)) {
            return false;
        }

        if (!preferred_address->id.write_to(iob)) {
            return false;
        }

        if (!iob->write(preferred_address->stateless_reset_token.data(), 16)) {
            return false;
        }

        return true;
    }

    static bool __unpack_preferred_address(
        io_buffer *iob, 
        transport_preferred_address *preferred_address) {
        sockaddr_in addr_v4;
        if (!iob->read((block_t*)&addr_v4.sin_addr.s_addr, 4) ||
            !iob->read((block_t*)&addr_v4.sin_port, 2)) {
            return false;
        }
        preferred_address->ipv4.set((const struct sockaddr*)&addr_v4, sizeof(sockaddr_in));

        sockaddr_in6 addr_v6;
        if (!iob->read((block_t*)&addr_v6.sin6_addr, 16) ||
            !iob->read((block_t*)&addr_v6.sin6_port, 2)) {
            return false;
        }
        preferred_address->ipv6.set((const struct sockaddr*)&addr_v6, sizeof(sockaddr_in6));

        block_t len;
        if (!iob->read(&len) ||
            !preferred_address->id.read_from(iob, len)) {
            return false;
        }

        preferred_address->stateless_reset_token.resize(16);
        if (!read_string_from_iob(iob, preferred_address->stateless_reset_token)) {
            return false;
        }

        return true;
    }

    bool pack_parameters(
        stream_initiator_type initiator,
        const transport_parameters *params, 
        io_buffer *iob) {

        if (initiator == server_initiator) {
            if (!varint_encode(PARAM_ORIGINAL_DESTINATION_CONNECTION_ID, iob) || 
                !varint_encode(params->original_destination_cid.length(), iob) ||
                !params->original_destination_cid.write_to(iob)) {
                return false;
            }
        }

        if (!varint_encode(PARAM_MAX_IDLE_TIMEOUT, iob) || 
            !varint_encode(varint_length(params->max_idle_timeout), iob) ||
            !varint_encode(params->max_idle_timeout, iob) ) {
            return false;
        }

        if (initiator == server_initiator && params->stateless_reset_token.size() == 16) {
            if (!varint_encode(PARAM_STATELESS_RESET_TOKEN, iob) || 
                !varint_encode(16, iob) ||
                !write_string_to_iob(params->stateless_reset_token, iob)) {
                return false;
            }
        }

        if (params->max_udp_payload_size > 0) {
            if (!varint_encode(PARAM_MAX_UDP_PAYLOAD_SIZE, iob) || 
                !varint_encode(varint_length(params->max_udp_payload_size), iob) ||
                !varint_encode(params->max_udp_payload_size, iob) ) {
                return false;
            }
        }
    
        if (!varint_encode(PARAM_INITIAL_MAX_DATA, iob) || 
            !varint_encode(varint_length(params->initial_max_data), iob) ||
            !varint_encode(params->initial_max_data, iob)) {
            return false;
        }

        if (!varint_encode(PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, iob) || 
            !varint_encode(varint_length(params->initial_max_stream_data_bidi_local), iob) ||
            !varint_encode(params->initial_max_stream_data_bidi_local, iob)) {
            return false;
        }

        if (!varint_encode(PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, iob) || 
            !varint_encode(varint_length(params->initial_max_stream_data_bidi_remote), iob) ||
            !varint_encode(params->initial_max_stream_data_bidi_remote, iob)) {
            return false;
        }

        if (!varint_encode(PARAM_INITIAL_MAX_STREAM_DATA_UNI, iob) || 
            !varint_encode(varint_length(params->initial_max_stream_data_uni), iob) ||
            !varint_encode(params->initial_max_stream_data_uni, iob)) {
            return false;
        }

        if (!varint_encode(PARAM_INITIAL_MAX_STREAMS_BIDI, iob) || 
            !varint_encode(varint_length(params->max_streams_bidi), iob) ||
            !varint_encode(params->max_streams_bidi, iob)) {
            return false;
        }

        if (!varint_encode(PARAM_INITIAL_MAX_STREAMS_UNI, iob) || 
            !varint_encode(varint_length(params->max_streams_uni), iob) ||
            !varint_encode(params->max_streams_uni, iob)) {
            return false;
        }

        if (params->ack_delay_exponent != DEF_ACK_DELAY_EXPONENT) {
            if (!varint_encode(PARAM_ACK_DELAY_EXPONENT, iob) || 
                !varint_encode(varint_length(params->ack_delay_exponent), iob) ||
                !varint_encode(params->ack_delay_exponent, iob)) {
                return false;
            }
        }

        if (params->max_ack_delay != DEF_MAX_ACK_DELAY) {
            if (!varint_encode(PARAM_MAX_ACK_DELAY, iob) || 
                !varint_encode(varint_length(params->max_ack_delay), iob) ||
                !varint_encode(params->max_ack_delay, iob)) {
                return false;
            }
        }

        if (params->disable_active_migration) {
            if (!varint_encode(PARAM_DISABLE_ACTIVE_MIGRATION, iob) || 
                !varint_encode(0, iob)) {
                return false;
            }
        }

        if (initiator == server_initiator && params->preferred_address != nullptr) {
            if (!varint_encode(PARAM_PREFERRED_ADDRESS, iob) || 
                !varint_encode(4 + 2 + 16 + 2 + 1 + params->preferred_address->id.length() + 16, iob) ||
                !__pack_preferred_address(params->preferred_address, iob) ||
                !write_string_to_iob(params->preferred_address->stateless_reset_token, iob)) {
                return false;
            }
        }

        if (!varint_encode(PARAM_ACTIVE_CONNECTION_ID_LIMIT, iob) || 
            !varint_encode(varint_length(params->active_connection_id_limit), iob) ||
            !varint_encode(params->active_connection_id_limit, iob)) {
            return false;
        }

        if (!varint_encode(PARAM_INITIAL_SOURCE_CONNECTION_ID, iob) || 
            !varint_encode(varint_length(params->initial_source_connection_id.length()), iob) ||
            !params->initial_source_connection_id.write_to(iob)) {
            return false;
        }

        if (initiator == server_initiator && params->retry_source_connection_id.length() > 0) {
            if (!varint_encode(PARAM_RETRY_SOURCE_CONNECTION_ID, iob) || 
                !varint_encode(varint_length(params->retry_source_connection_id.length()), iob) ||
                !params->retry_source_connection_id.write_to(iob)) {
                return false;
            }
        }

        if (params->max_datagram_frame_size > 0) {
            if (!varint_encode(PARAM_RETRY_SOURCE_CONNECTION_ID, iob) || 
                !varint_encode(varint_length(params->max_datagram_frame_size), iob)) {
                return false;
            }
        }

        return true;
    }

    bool unpack_parameters(
        stream_initiator_type initiator,
        io_buffer *iob, 
        transport_parameters *params) {
        if (iob == nullptr || params == nullptr) {
            return false;
        }

        while (iob->size() > 0) {
            transport_parameter_type pt;
            if (!varint_decode(iob, &pt)) {
                return false;
            }

            uint64_t len = 0;
            if (!varint_decode(iob, &len)) {
                return false;
            } else if (len > iob->size()) {
                 return false;
            }

            switch (pt)
            {
            case PARAM_ORIGINAL_DESTINATION_CONNECTION_ID:
                if (initiator == client_initiator) {
                    return false;
                } else if (!params->original_destination_cid.read_from(iob, len)) {
                    return false;
                }
                break;
            case PARAM_MAX_IDLE_TIMEOUT:
                if (!varint_decode_ex(iob, &params->max_idle_timeout)) {
                    return false;
                }
                if (params->max_idle_timeout < DEF_MIN_REMOTE_IDLE_TIMEOUT) {
                    params->max_idle_timeout = DEF_MIN_REMOTE_IDLE_TIMEOUT;
                }
                break;
            case PARAM_STATELESS_RESET_TOKEN:
                if (initiator == client_initiator) {
                    return false;
                } else if (len != 16) {
                    return false;
                }
                params->stateless_reset_token.resize(16);
                if (!read_string_from_iob(iob, params->stateless_reset_token)) {
                    return false;
                }
                break;
            case PARAM_MAX_UDP_PAYLOAD_SIZE:
                if (!varint_decode_ex(iob, &params->max_udp_payload_size)) {
                    return false;
                } else if (params->max_udp_payload_size < 1200) {
                    return false;
                }
                break;
            case PARAM_INITIAL_MAX_DATA:
                if (!varint_decode_ex(iob, &params->initial_max_data)) {
                    return false;
                } 
                break;
            case PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
                if (!varint_decode_ex(iob, &params->initial_max_stream_data_bidi_local)) {
                    return false;
                } 
                break;
            case PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
                if (!varint_decode_ex(iob, &params->initial_max_stream_data_bidi_remote)) {
                    return false;
                } 
                break;
            case PARAM_INITIAL_MAX_STREAM_DATA_UNI:
                if (!varint_decode_ex(iob, &params->initial_max_stream_data_uni)) {
                    return false;
                }
                break;
            case PARAM_INITIAL_MAX_STREAMS_BIDI:
                if (!varint_decode_ex(iob, &params->max_streams_bidi)) {
                    return false;
                } else if (params->max_streams_bidi > MAX_STREAM_COUNT) {
                    return false;
                }
                break;
            case PARAM_INITIAL_MAX_STREAMS_UNI:
                if (!varint_decode_ex(iob, &params->max_streams_uni)) {
                    return false;
                } else if (params->max_streams_uni > MAX_STREAM_COUNT) {
                    return false;
                }
                break;
            case PARAM_ACK_DELAY_EXPONENT:
                if (!varint_decode_ex(iob, &params->ack_delay_exponent)) {
                    return false;
                } else if (params->ack_delay_exponent > DEF_ACK_DELAY_EXPONENT) {
                    return false;
                }
                break;
            case PARAM_MAX_ACK_DELAY:
                if (!varint_decode_ex(iob, &params->max_ack_delay)) {
                    return false;
                } else if (params->max_ack_delay > MAX_MAX_ACK_DELAY) {
                    return false;
                }
                break;
            case PARAM_DISABLE_ACTIVE_MIGRATION:
                if (len != 0) {
                    return false;
                }
                params->disable_active_migration = true;
                break;
            case PARAM_PREFERRED_ADDRESS:
                if (initiator == client_initiator) {
                    return false;
                } else if (params->preferred_address != nullptr) {
                    return false;
                } else {
                    params->preferred_address = object_create<transport_preferred_address>();
                    if (params->preferred_address != nullptr) {
                        return false;
                    }
                }
                if (!__unpack_preferred_address(iob, params->preferred_address)) {
                    return false;
                }
                break;
            case PARAM_ACTIVE_CONNECTION_ID_LIMIT:
                if (!varint_decode_ex(iob, &params->active_connection_id_limit)) {
                    return false;
                }
                break;
            case PARAM_INITIAL_SOURCE_CONNECTION_ID:
                if (!params->initial_source_connection_id.read_from(iob, len)) {
                    return false;
                }
                break;
            case PARAM_RETRY_SOURCE_CONNECTION_ID:
                if (initiator == client_initiator) {
                    return false;
                } else if (!params->retry_source_connection_id.read_from(iob, len)) {
                    return false;
                }
                break;
            case PARAM_MAX_DATAGRAM_FRAME_SIZE:
                if (!varint_decode_ex(iob, &params->max_datagram_frame_size)) {
                    return false;
                }
                break;
            default:
                iob->shift(len);
                break;
            }
        }

        return true;
    }

    tls::extension_type get_paramerters_extension_type(version_number version) {
        if (version == version_tls) {
            return 0x39;
        }
        return 0xffa5;
    }

}
}
}