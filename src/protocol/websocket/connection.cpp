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

    connection::connection(service_ptr sv,
                           transport::base_transport_sptr &transp,
                           bool has_mask) noexcept
      : sv_(sv),
        transp_(transp),
        rt_(READ_NONE),
        has_mask_(has_mask),
        decode_phase_(DECODE_FRAME_HEADER) {
        if (has_mask_) {
            *(uint32_t*)(mask_key_) = (uint32_t)::time(0);
        } else {
            memset(mask_key_, 0, sizeof(mask_key_));
        }

        closed_.clear();
    }

    bool connection::start_upgrade(bool client, const upgrade_callbacks &ucbs) {
        PUMP_LOCK_SPOINTER(transp, transp_);
        if (!transp || transp->is_started()) {
            return false;
        }

        if (!ucbs.pocket_cb || !ucbs.error_cb) {
            return false;
        }

        ucbs_ = ucbs;

        transport::transport_callbacks tcbs;
        connection_wptr wptr = shared_from_this();
        tcbs.read_cb = pump_bind(&connection::on_read, wptr, _1, _2);
        tcbs.stopped_cb = pump_bind(&connection::on_stopped, wptr);
        tcbs.disconnected_cb = pump_bind(&connection::on_disconnected, wptr);
        if (transp->start(sv_, tcbs) != transport::ERROR_OK) {
            return false;
        }

        rt_ = READ_POCKET;

        PUMP_ASSERT(!pocket_);
        PUMP_ASSERT(decode_phase_ == DECODE_FRAME_HEADER);

        if (client) {
            pocket_.reset(new http::response);
        } else {
            pocket_.reset(new http::request);
        }

        if (transp->read_for_once() != transport::ERROR_OK) {
            return false;
        }

        return true;
    }

    bool connection::start(const connection_callbacks &cbs) {
        PUMP_ASSERT(!pocket_);
        PUMP_ASSERT(decode_phase_ == DECODE_FRAME_HEADER);

        PUMP_LOCK_SPOINTER(transp, transp_);
        if (!transp || !transp->is_started()) {
            return false;
        }

        if (!cbs.frame_cb || !cbs.error_cb) {
            return false;
        }

        cbs_ = cbs;

        rt_ = READ_FRAME;

        if (transp->read_for_loop() != transport::ERROR_OK) {
            return false;
        }

        return true;
    }

    void connection::stop() {
        PUMP_LOCK_SPOINTER(transp, transp_);
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

    bool connection::async_read_next_frame() {
        PUMP_ASSERT(!pocket_);
        PUMP_ASSERT(decode_phase_ == DECODE_FRAME_HEADER);

        PUMP_LOCK_SPOINTER(transp, transp_);
        if (!transp || !transp->is_started()) {
            return false;
        }

        rt_ = READ_FRAME;

        if (transp->read_for_once() != transport::ERROR_OK) {
            return false;
        }

        return true;
    }

    bool connection::send_buffer(const block_t *b, int32_t size) {
        PUMP_LOCK_SPOINTER(transp, transp_);
        if (!transp || !transp->is_started()) {
            return false;
        }

        if (transp->send(b, size) != transport::ERROR_OK) {
            return false;
        }

        return true;
    }

    bool connection::send(const block_t *b, int32_t size) {
        PUMP_LOCK_SPOINTER(transp, transp_);
        if (!transp || !transp->is_started()) {
            return false;
        }

        frame_header hdr;
        init_frame_header(&hdr, 1, FRAME_OPTCODE_TEXT, has_mask_, mask_key_, size);
        int32_t hdr_size = get_frame_header_size(&hdr);

        // Encode frame header
        std::string buffer(hdr_size, 0);
        if (encode_frame_header(&hdr, (block_t*)buffer.c_str(), hdr_size) == 0) {
            PUMP_ASSERT(false);
        }

        // Append frame payload
        buffer.append(b, size);
        // Make mask payload data if having mask
        if (has_mask_) {
            mask_transform((uint8_t*)(buffer.data() + hdr_size), size, mask_key_);
        }

        // Send frame
        if (transp->send(buffer.c_str(), (int32_t)buffer.size()) !=
            transport::ERROR_OK) {
            return false;
        }

        return true;
    }

    void connection::on_read(connection_wptr wptr, const block_t *b, int32_t size) {
        PUMP_LOCK_WPOINTER(conn, wptr);
        if (conn) {
            if (!conn->read_cache_.empty()) {
                conn->read_cache_.append(b, size);
                b = conn->read_cache_.data();
                size = (int32_t)conn->read_cache_.size();
            }

            int32_t used_size = -1;
            if (conn->rt_ == READ_FRAME) {
                used_size = conn->__handle_frame(b, size);
            } else if (conn->rt_ > READ_FRAME) {
                used_size = conn->__handle_pocket(b, size);
            }

            if (used_size < 0) {
                conn->transp_->stop();
                return;
            }

            if (conn->read_cache_.empty()) {
                if (size > used_size) {
                    conn->read_cache_.append(b + used_size, size - used_size);
                }
            } else {
                conn->read_cache_ = conn->read_cache_.substr(used_size);
            }
        }
    }

    void connection::on_disconnected(connection_wptr wptr) {
        PUMP_LOCK_WPOINTER(conn, wptr);
        if (conn) {
            if (!conn->closed_.test_and_set()) {
                conn->cbs_.error_cb("websocket connection disconnected");
            }
        }
    }

    void connection::on_stopped(connection_wptr wptr) {
        PUMP_LOCK_WPOINTER(conn, wptr);
        if (conn) {
            if (!conn->closed_.test_and_set()) {
                conn->cbs_.error_cb("websocket connection stopped");
            }
        }
    }

    int32_t connection::__handle_pocket(const block_t *b, int32_t size) {
        auto pk = pocket_.get();
        PUMP_ASSERT(pk);

        int32_t parse_size = -1;
        if (read_cache_.empty()) {
            parse_size = pk->parse(b, size);
            if (parse_size >= 0 && parse_size < size) {
                read_cache_.append(b + parse_size, size - parse_size);
            }
        } else {
            read_cache_.append(b, size);
            parse_size = pk->parse(read_cache_.data(), (int32_t)read_cache_.size());
            if (parse_size > 0) {
                read_cache_ = read_cache_.substr(parse_size);
            }
        }

        if (parse_size == -1) {
            return -1;
        }

        if (pk->is_parse_finished()) {
            ucbs_.pocket_cb(std::move(pocket_));
        } else {
            transp_->read_for_once();
        }

        return parse_size;
    }

    int32_t connection::__handle_frame(const block_t *b, int32_t size) {
        int32_t hdr_size = 0;
        int32_t payload_size = 0;

        if (decode_phase_ == DECODE_FRAME_HEADER) {
            hdr_size = decode_frame_header(b, size, &decode_hdr_);
            if (hdr_size <= 0) {
                return hdr_size;
            }

            decode_phase_ = DECODE_FRAME_PAYLOAD;
        }

        if (decode_phase_ == DECODE_FRAME_PAYLOAD) {
            payload_size = (int32_t)decode_hdr_.payload_len;
            if (payload_size > 126) {
                payload_size = (int32_t)decode_hdr_.ex_payload_len;
            }

            if (hdr_size + payload_size > size) {
                return hdr_size;
            }

            decode_phase_ = DECODE_FRAME_HEADER;

            if (payload_size > 0 && decode_hdr_.mask == 1) {
                mask_transform((uint8_t*)(b + hdr_size), payload_size, decode_hdr_.mask_key);
            }

            uint32_t optcode = decode_hdr_.optcode;
            if (optcode == FRAME_OPTCODE_SEQUEL || optcode == FRAME_OPTCODE_TEXT ||
                optcode == FRAME_OPTCODE_BINARY) {
                cbs_.frame_cb(b + hdr_size, payload_size, decode_hdr_.fin == 1);
            } else if (optcode == FRAME_OPTCODE_CLOSE) {
                if (!closed_.test_and_set()) {
                    // Send close frame response
                    __send_close_frame();
                    // Stop http connection
                    transp_->stop();
                    // Tagger error callback
                    cbs_.error_cb("websocket connection closed");
                }
            } else if (optcode == FRAME_OPTCODE_PING) {
                __send_pong_frame();
            } else if (optcode == FRAME_OPTCODE_PONG) {
                // TODO:
            } else {
                return -1;
            }

            transp_->read_for_once();
        }

        return hdr_size + payload_size;
    }

    void connection::__send_ping_frame() {
        frame_header hdr;
        init_frame_header(&hdr, 1, FRAME_OPTCODE_PING, 0, 0, 0);
        uint32_t hdr_size = get_frame_header_size(&hdr);

        std::string buffer(hdr_size, 0);
        if (encode_frame_header(&hdr, (block_t*)buffer.c_str(), hdr_size) == 0) {
            PUMP_ASSERT(false);
        }

        transp_->send(buffer.c_str(), (int32_t)buffer.size());
    }

    void connection::__send_pong_frame() {
        frame_header hdr;
        init_frame_header(&hdr, 1, FRAME_OPTCODE_PONG, 0, 0, 0);
        int32_t hdr_size = get_frame_header_size(&hdr);

        std::string buffer(hdr_size, 0);
        if (encode_frame_header(&hdr, (block_t*)buffer.c_str(), hdr_size) == 0) {
            PUMP_ASSERT(false);
        }

        transp_->send(buffer.c_str(), (int32_t)buffer.size());
    }

    void connection::__send_close_frame() {
        frame_header hdr;
        init_frame_header(&hdr, 1, FRAME_OPTCODE_CLOSE, 0, 0, 0);
        int32_t hdr_size = get_frame_header_size(&hdr);

        std::string buffer(hdr_size, 0);
        if (encode_frame_header(&hdr, (block_t*)buffer.c_str(), hdr_size) == 0) {
            PUMP_ASSERT(false);
        }

        transp_->send(buffer.c_str(), (int32_t)buffer.size());
    }

}  // namespace websocket
}  // namespace protocol
}  // namespace pump
