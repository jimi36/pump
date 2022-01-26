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
#include "pump/proto/quic/utils.h"
#include "pump/proto/quic/packets.h"

namespace pump {
namespace proto {
namespace quic {

    static bool __pack_packet_number(uint8_t len, uint32_t num, io_buffer *iob) {
        if (len == 1) {
            return iob->write(num);
        } else if (len == 2) {
            uint16_t n = transform_endian_i16(num);
            return iob->write((block_t*)&n, sizeof(n));
        } else if (len == 3) {
            uint32_t n = transform_endian_i32(num);
            return iob->write((block_t*)&n + 1, sizeof(n) - 1);
        } else if (len == 4) {
            uint32_t n = transform_endian_i32(num);
            return iob->write((block_t*)&n, sizeof(n));
        }
        return false;
    }

    static bool __unpack_packet_number(io_buffer *iob, uint8_t len, uint32_t *num) {
        if (len == 1) {
            uint8_t n = 0;
            if (iob->read((block_t*)&n)) {
                *num = n;
                return true;
            }
        } else if (len == 2) {
            uint16_t n = 0;
            if (iob->read((block_t*)&n, sizeof(n))) {
                *num = transform_endian_i16(n);
                return true;
            }
        } else if (len == 3) {
            uint32_t n = 0;
            if (iob->read((block_t*)&n + 1, sizeof(n) - 1)) {
                *num = transform_endian_i32(n);
                return true;
            }
        } else if (len == 4) {
            uint32_t n = 0;
            if (iob->read((block_t*)&n, sizeof(n))) {
                *num = transform_endian_i32(n);
                return true;
            }
        }
        return false;
    }

    static bool __pack_long_packet_header(const packet_header *hdr, io_buffer *b) {
        uint8_t hb = 0xc0;
        if (hdr->packet_type != LPT_NEGOTIATE_VER) {
            hb |= uint8_t(hdr->packet_type << 4);
            if (hdr->packet_type != LPT_RETRY) {
                hb |= (hdr->packet_number_len - 1);
            }
        }
        b->write(block_t(hb));

        uint32_t b4 = transform_endian_i32(hdr->version);
        b->write((const block_t*)&b4, sizeof(b4));

        b->write((block_t)hdr->des_id.length());
        b->write(hdr->des_id.data(), hdr->des_id.length());

        b->write((block_t)hdr->src_id.length());
        b->write(hdr->src_id.data(), hdr->src_id.length());

        return true;
    }

    static bool __unpack_long_packet_header(io_buffer *iob, uint8_t hb, packet_header *hdr) {
        if (!iob->read((block_t*)&hdr->version, sizeof(hdr->version))) {
            return false;
        }
        if (hdr->version == 0) {
            hdr->packet_type = LPT_NEGOTIATE_VER;
        } else {
            hdr->packet_type = (hb >> 4) & 0x0F;
            hdr->version = transform_endian_i32(hdr->version);
        }

        uint8_t des_id_len = 0;
        if (!iob->read((block_t*)&des_id_len)) {
            return false;
        }
        if (des_id_len > 0 && !hdr->des_id.read_from(iob, des_id_len)) {
            return false;
        }
        
        uint8_t src_id_len = 0;
        if (!iob->read((block_t*)&src_id_len)) {
            return false;
        }
        if (src_id_len > 0 && !hdr->src_id.read_from(iob, src_id_len)) {
            return false;
        }       

        hdr->is_long_pakcet = true;

        return true;
    }

    static bool __pack_short_packet_header(const packet_header *hdr, io_buffer *b) {
        uint8_t hb = 0xc0;
        hb |= uint8_t(hdr->packet_type << 4);
        if (hdr->packet_type != LPT_RETRY) {
            hb |= uint8_t(hdr->packet_number_len - 1);
        }
        b->write(block_t(hb));

        b->write((block_t)hdr->des_id.length());
        b->write(hdr->des_id.data(), hdr->des_id.length());

        return true;
    }

    static bool __unpack_short_packet_header(io_buffer *iob, uint8_t id_len, uint8_t hb, packet_header *hdr) {
        if (!hdr->des_id.read_from(iob, id_len)) {
            return false;
        } 

        hdr->is_long_pakcet = false;

        return true;
    }

    static bool __pack_version_negotiation_packet(const packet *pkt, io_buffer *iob) {
        auto impl = (version_negotiation_packet*)pkt->ptr;

        for (uint32_t version : impl->supported_versions) {
            version = transform_endian_i32(version);
            if (!iob->write((block_t*)&version, sizeof(uint32_t))) {
                return false;
            }
        }

        return true;
    }

    static bool __unpack_version_negotiation_packet(io_buffer *iob, packet *pkt) {
        if (iob->size() % sizeof(uint32_t) != 0) {
            return false;
        }

        auto impl = object_create<version_negotiation_packet>();
        if (impl == nullptr) {
            return false;
        }
        for (uint32_t version = 0; iob->read((block_t*)&version, sizeof(version));) {
            impl->supported_versions.push_back(transform_endian_i32(version));
        }

        pkt->ptr = impl;

        return true;
    }

    static bool __pack_initial_packet(const packet *pkt, io_buffer *iob) {
        auto impl = (initial_packet*)pkt->ptr;

        if (!varint_encode(impl->token.size(), iob)) {
            return false;
        }
        if (!iob->write(impl->token.data(), impl->token.size())) {
            return false;
        }

        if (!varint_encode(impl->length, iob)) {
            return false;
        }

        if (!__pack_packet_number(pkt->header.packet_number_len, impl->packet_number, iob)) {
            return false;
        }

        return true;

    }

    static bool __unpack_initial_packet(io_buffer *iob, packet *pkt) {
        auto impl = object_create<initial_packet>();
        if (impl == nullptr) {
            return false;
        }
        pkt->ptr = impl;

        uint64_t token_len = 0;
        if (!varint_decode(iob, &token_len)) {
            return false;
        }
        impl->token.resize(token_len);
        if (!read_string_from_iob(iob, impl->token)) {
            return false;
        }

        uint64_t length = 0;
        if (!varint_decode(iob, &length)) {
            return false;
        }
        impl->length = length;

        if (!__unpack_packet_number(iob, pkt->header.packet_number_len, &impl->packet_number)) {
            return false;
        }

        return true;
    }

    packet* new_packet() {
        return object_create<packet>();
    }

    packet* new_short_packet() {
        packet *pkt = object_create<packet>();
        if (pkt != nullptr) {
            pkt->header.is_long_pakcet = false;
            pkt->ptr = object_create<one_rtt_packet>();
            if (pkt->ptr == nullptr) {
                object_delete(pkt);
                pkt = nullptr;
            }
        }
        return pkt;
    }

    packet* new_long_packet(long_packet_type type) {
        packet *pkt = object_create<packet>();
        if (pkt != nullptr) {
            pkt->header.is_long_pakcet = true;
            pkt->header.packet_type = type;
            switch(type) {
            case LPT_NEGOTIATE_VER:
                pkt->ptr = object_create<version_negotiation_packet>();
                break;
            case LPT_INITIAL:
                pkt->ptr = object_create<initial_packet>();
                break;
            case LPT_0RTT:
                pkt->ptr = object_create<zero_rtt_packet>();
                break;
            case LPT_HANDSHAKE:
                pkt->ptr = object_create<handshake_packet>();
                break;
            case LPT_RETRY:
                pkt->ptr = object_create<retry_packet>();
                break;
            default:
                PUMP_ABORT();
            }
            if (pkt->ptr == nullptr) {
                object_delete(pkt);
                pkt = nullptr;
            }
        }
        return pkt;
    }

    void delete_packet(packet *pkt) {
        if (pkt == nullptr) {
            return;
        }

        if (pkt->ptr != nullptr) {
            if (pkt->header.is_long_pakcet) {
                switch(pkt->header.packet_type) {
                case LPT_NEGOTIATE_VER:
                    object_delete((version_negotiation_packet*)pkt->ptr);
                    break;
                case LPT_INITIAL:
                    object_delete((initial_packet*)pkt->ptr);
                    break;
                case LPT_0RTT:
                    object_delete((zero_rtt_packet*)pkt->ptr);
                    break;
                case LPT_HANDSHAKE:
                    object_delete((handshake_packet*)pkt->ptr);
                    break;
                case LPT_RETRY:
                    object_delete((retry_packet*)pkt->ptr);
                    break;
                default:
                    PUMP_ABORT();
                }
            } else {
                object_delete((one_rtt_packet*)pkt->ptr);
            }
        }

        object_delete(pkt);
    }

    bool pack_packet(const packet *pkt, io_buffer *iob) {
        if (pkt->header.is_long_pakcet) {
            if (!__pack_long_packet_header(&pkt->header, iob)) {
                return false;
            }

        } else {
            if (!__pack_short_packet_header(&pkt->header, iob)) {
                return false;
            }
        }

        return true;
    }

    bool unpack_packet(io_buffer *iob, uint8_t id_len, packet *pkt) {
        uint8_t hb = 0;
        if (!iob->read((block_t*)&hb)) {
            return false;
        }

        if (hb > 0x80) {
            if (!__unpack_long_packet_header(iob, hb, &pkt->header)) {
                return false;
            }
        } else {
            if (!__unpack_short_packet_header(iob, id_len, hb, &pkt->header)) {
                return false;
            }
        }

        return true;
    }

}
}
}