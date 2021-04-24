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

#include "pump/protocol/websocket/utils.h"
#include "pump/protocol/websocket/connection.h"

namespace pump {
namespace protocol {
namespace websocket {

    const static int32_t READ_NONE = 0;
    const static int32_t READ_FRAME = 1;
    const static int32_t READ_POCKET = 2;

    const static int32_t DECODE_FRAME_HEADER = 0;
    const static int32_t DECODE_FRAME_PAYLOAD = 1;

    connection::connection(
        service *sv,
        transport::base_transport_sptr &transp,
        bool has_mask) noexcept
      : sv_(sv),
        transp_(transp),
        read_category_(READ_NONE),
        cahce_(nullptr),
        has_mask_(has_mask),
        decode_phase_(DECODE_FRAME_HEADER) {
        *(uint32_t*)(mask_key_) = (uint32_t)::time(0);
        closed_.clear();
    }

    bool connection::start_upgrade(
        bool client, 
        const upgrade_callbacks &ucbs) {
        auto transp = transp_;
        PUMP_DEBUG_FAILED(
            !transp || transp->is_started(),
            "websocket::connection: start upgrade failed for transport invalid or already started",
            return false);

        PUMP_DEBUG_FAILED (
            !ucbs.pocket_cb || !ucbs.error_cb,
            "websocket::connection: start upgrade failed for callbacks invalid",
            return false);
        ucbs_ = ucbs;

        PUMP_DEBUG_FAILED(
            cahce_ != nullptr,
            "websocket::connection: start upgrade failed for cahce already exists",
            return false);

        if ((cahce_ = toolkit::io_buffer::create()) == nullptr) {
            PUMP_WARN_LOG("websocket::connection: start upgrade failed for creating cache failed");
            return false;
        }

        if (client) {
            pocket_.reset(
                object_create<http::response>(), 
                object_delete<http::response>);
        } else {
            pocket_.reset(
                object_create<http::request>(), 
                object_delete<http::request>);
        }
        if (!pocket_) {
            PUMP_WARN_LOG("websocket::connection: start upgrade failed for creating pocket failed");
            return false;
        }

        PUMP_DEBUG_FAILED (
            read_category_ != READ_NONE,
            "websocket::connection: start failed for read type incorrect",
            return false);
        read_category_ = READ_POCKET;

        transport::transport_callbacks tcbs;
        connection_wptr wptr = shared_from_this();
        tcbs.read_cb = pump_bind(&connection::on_read, wptr, _1, _2);
        tcbs.stopped_cb = pump_bind(&connection::on_stopped, wptr);
        tcbs.disconnected_cb = pump_bind(&connection::on_disconnected, wptr);
        if (transp->start(sv_, tcbs) != transport::ERROR_OK) {
            PUMP_DEBUG_LOG("websocket::connection: start upgrade failed for starting transport failed");
            return false;
        }
        if (transp->read_for_once() != transport::ERROR_OK) {
            PUMP_DEBUG_LOG("websocket::connection: start upgrade failed for reading once failed");
            return false;
        }

        return true;
    }

    bool connection::start(const connection_callbacks &cbs) {
        auto transp = transp_;
        PUMP_DEBUG_FAILED(
            !transp || !transp->is_started(),
            "websocket::connection: start failed for transport invalid",
            return false);

        PUMP_DEBUG_FAILED(
            !cbs.frame_cb || !cbs.error_cb,
            "websocket::connection: start failed for callbacks invalid",
            return false);
        cbs_ = cbs;

        PUMP_DEBUG_FAILED (
            read_category_ != READ_POCKET,
            "websocket::connection: start failed for read type incorrect",
            return false);
        read_category_ = READ_FRAME;

        if (transp->read_for_loop() != transport::ERROR_OK) {
            PUMP_DEBUG_LOG("websocket::connection: start failed for reading once failed");
            return false;
        }

        return true;
    }

    void connection::stop() {
        auto transp = transp_;
        if (!transp || !transp->is_started()) {
            return;
        }

        if (!closed_.test_and_set()) {
            // Send close frame
            __send_close_frame();
            // Stop transport
            transp->stop();
        }
    }

    bool connection::send(
        const block_t *b, 
        int32_t size) {
        auto transp = transp_;
        if (!transp || !transp->is_started()) {
            PUMP_DEBUG_LOG("websocket::connection: send failed for transport invalid");
            return false;
        }

        if (transp->send(b, size) != transport::ERROR_OK) {
            PUMP_DEBUG_LOG("websocket::connection: send failed for transport sending failed");
            return false;
        }

        return true;
    }

    bool connection::send_frame(
        const block_t *b, 
        int32_t size) {
        auto transp = transp_;
        if (!transp || !transp->is_started()) {
            PUMP_DEBUG_LOG("websocket::connection: send frame failed for transport invalid");
            return false;
        }

        frame_header hdr;
        init_frame_header(&hdr, 1, FRAME_OPTCODE_TEXT, has_mask_, mask_key_, size);
        int32_t hdr_size = get_frame_header_size(&hdr);

        // Encode frame header
        std::string buffer(hdr_size + size, 0);
        if (encode_frame_header(&hdr, (block_t*)buffer.c_str(), hdr_size) == 0) {
            PUMP_DEBUG_LOG("websocket::connection: send frame failed for encoding frame header failed");
            return false;
        }

        // Copy frame payload
        memcpy((void*)(buffer.data() + hdr_size), b, size);

        // Mark payload data if having mask
        if (has_mask_) {
            mask_transform(
                (uint8_t*)(buffer.data() + hdr_size), 
                size, 
                mask_key_);
        }

        // Send frame
        if (transp->send(buffer.c_str(), (int32_t)buffer.size()) != transport::ERROR_OK) {
            PUMP_DEBUG_LOG("websocket::connection: send frame failed for transport sending failed");
            return false;
        }

        return true;
    }

    void connection::on_read(
        connection_wptr wptr, 
        const block_t *b,
        int32_t size) {
        auto conn = wptr.lock();
        if (conn) {
            if (conn->cahce_->data_size() > 0) {
                if (!conn->cahce_->append(b, size)) {
                    PUMP_WARN_LOG("websocket::connection: read failed for cache appending failed");
                    return;
                }
                b = conn->cahce_->data();
                size = (int32_t)conn->cahce_->data_size();
            }

            int32_t used_size = -1;
            if (conn->read_category_ == READ_FRAME) {
                used_size = conn->__handle_frame(b, size);
            } else if (conn->read_category_ == READ_POCKET) {
                used_size = conn->__handle_pocket(b, size);
            } else {
                PUMP_ABORT();
            }

            if (used_size < 0) {
                conn->transp_->stop();
                return;
            }

            if (conn->cahce_->data_size() == 0) {
                if (size > used_size) {
                    conn->cahce_->append(b + used_size, size - used_size);
                }
            } else {
                conn->cahce_->shift(used_size);
            }
        }
    }

    void connection::on_disconnected(connection_wptr wptr) {
        auto conn = wptr.lock();
        if (conn) {
            if (!conn->closed_.test_and_set() && conn->cbs_.error_cb) {
                conn->cbs_.error_cb("websocket connection disconnected");
            }
        }
    }

    void connection::on_stopped(connection_wptr wptr) {
        auto conn = wptr.lock();
        if (conn) {
            if (!conn->closed_.test_and_set() && conn->cbs_.error_cb) {
                conn->cbs_.error_cb("websocket connection stopped");
            }
        }
    }

    int32_t connection::__handle_pocket(
        const block_t *b, 
        int32_t size) {
        if (!pocket_) {
            return -1;
        }
        int32_t parse_size = pocket_->parse(b, size);
        if (parse_size < 0) {
            PUMP_DEBUG_LOG(
                "websocket::connection: handle pocket failed for parsing pocket failed");
            return -1;
        }

        if (pocket_->is_parse_finished()) {
            ucbs_.pocket_cb(std::move(pocket_));
        } else {
            if (transp_->read_for_once() != transport::ERROR_OK) {
                PUMP_DEBUG_LOG(
                    "websocket::connection: handle pocket failed for reading once failed");
                return -1;
            }
        }
        
        return parse_size;
    }

    int32_t connection::__handle_frame(const block_t *b, int32_t size) {
        int32_t parse_size = 0;

        do {
            if (decode_phase_ == DECODE_FRAME_HEADER) {
                if ((parse_size = decode_frame_header(b, size, &decode_hdr_)) <= 0) {
                    PUMP_DEBUG_LOG(
                        "websocket::connection: handle frame failed for decoding frame header failed");
                    break;
                }

                decode_phase_ = DECODE_FRAME_PAYLOAD;
            }

            if (decode_phase_ == DECODE_FRAME_PAYLOAD) {
                int32_t frame_payload_size = (int32_t)decode_hdr_.payload_len;
                if (frame_payload_size > 126) {
                    frame_payload_size = (int32_t)decode_hdr_.ex_payload_len;
                }
                if (parse_size + frame_payload_size > size) {
                    break;
                }
                if (frame_payload_size > 0 && decode_hdr_.mask == 1) {
                    mask_transform(
                        (uint8_t*)(b + parse_size), 
                        frame_payload_size, 
                        decode_hdr_.mask_key);
                }

                switch (decode_hdr_.optcode)
                {
                case FRAME_OPTCODE_SEQUEL:
                case FRAME_OPTCODE_TEXT:
                case FRAME_OPTCODE_BINARY:
                    cbs_.frame_cb(
                        b + parse_size, 
                        frame_payload_size, 
                        decode_hdr_.fin == 1);
                    break;
                case FRAME_OPTCODE_CLOSE:
                {
                    if (!closed_.test_and_set()) {
                        // Send close frame response
                        __send_close_frame();
                        // Stop http connection
                        transp_->stop();
                        // Tagger error callback
                        cbs_.error_cb("websocket connection closed");
                    }
                    break;
                }
                case FRAME_OPTCODE_PING:
                    __send_pong_frame();
                    break;
                case FRAME_OPTCODE_PONG:
                    // TODO: do nothing?
                    break;
                default:
                    PUMP_DEBUG_LOG(
                        "websocket::connection: handle frame failed for unknown frame");
                    return -1;
                }

                parse_size += frame_payload_size;

                decode_phase_ = DECODE_FRAME_HEADER;
            }
        } while(false);

        if (transp_->read_for_once() != transport::ERROR_OK) {
            PUMP_DEBUG_LOG(
                "websocket::connection: handle frame failed for reading once failed");
            return -1;
        }

        return parse_size;
    }

    void connection::__send_ping_frame() {
        frame_header hdr;
        init_frame_header(&hdr, 1, FRAME_OPTCODE_PING, 0, 0, 0);
        uint32_t hdr_size = get_frame_header_size(&hdr);

        std::string buffer(hdr_size, 0);
        if (encode_frame_header(&hdr, (block_t*)buffer.c_str(), hdr_size) == 0) {
            PUMP_DEBUG_LOG(
                "websocket::connection: send ping frame failed for encoding frame header failed");
            return;
        }

        if (transp_->send(buffer.c_str(), (int32_t)buffer.size()) != transport::ERROR_OK) {
            PUMP_DEBUG_LOG(
                "websocket::connection: send ping frame failed for sending frame failed");
        }
    }

    void connection::__send_pong_frame() {
        frame_header hdr;
        init_frame_header(&hdr, 1, FRAME_OPTCODE_PONG, 0, 0, 0);
        int32_t hdr_size = get_frame_header_size(&hdr);

        std::string buffer(hdr_size, 0);
        if (encode_frame_header(&hdr, (block_t*)buffer.c_str(), hdr_size) == 0) {
            PUMP_DEBUG_LOG(
                "websocket::connection: send pong frame failed for encoding frame header failed");
            return;
        }

        if (transp_->send(buffer.c_str(), (int32_t)buffer.size()) != transport::ERROR_OK) {
            PUMP_DEBUG_LOG(
                "websocket::connection: send ping frame failed for sending frame failed");
        }
    }

    void connection::__send_close_frame() {
        frame_header hdr;
        init_frame_header(&hdr, 1, FRAME_OPTCODE_CLOSE, 0, 0, 0);
        int32_t hdr_size = get_frame_header_size(&hdr);

        std::string buffer(hdr_size, 0);
        if (encode_frame_header(&hdr, (block_t*)buffer.c_str(), hdr_size) == 0) {
            PUMP_DEBUG_LOG(
                "websocket::connection: send close frame failed for encoding frame header failed");
            return;
        }

        if (transp_->send(buffer.c_str(), (int32_t)buffer.size()) != transport::ERROR_OK) {
            PUMP_DEBUG_LOG(
                "websocket::connection: send ping frame failed for sending frame failed");
        }
    }

}  // namespace websocket
}  // namespace protocol
}  // namespace pump
