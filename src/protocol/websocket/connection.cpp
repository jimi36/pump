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

#define DECODE_FRAME_HEADER 0
#define DECODE_FRAME_PAYLOAD 1

        connection::connection(bool has_mask) noexcept
            : sv_(nullptr), has_mask_(has_mask), decode_phase_(DECODE_FRAME_HEADER) {
            closed_.clear();

            if (has_mask_)
                *(uint32_ptr)(mask_key_) = (uint32)::time(0);
            else
                memset(mask_key_, 0, sizeof(mask_key_));
        }

        bool connection::upgrade(http::connection_sptr &http_conn) {
            if (!http_conn || !http_conn->is_valid())
                return false;

            transport::transport_callbacks tcbs;
            connection_wptr wptr = shared_from_this();
            tcbs.read_cb = pump_bind(&connection::on_read, wptr, _1, _2);
            tcbs.stopped_cb = pump_bind(&connection::on_stopped, wptr);
            tcbs.disconnected_cb = pump_bind(&connection::on_disconnected, wptr);
            if (!http_conn->get_transport()->reset_callbacks(tcbs))
                return false;

            transp_ = http_conn->pop_transport();

            return true;
        }

        bool connection::start(const connection_callbacks &cbs) {
            PUMP_LOCK_SPOINTER(transp, transp_);
            if (transp == nullptr || !transp->is_started())
                return false;

            if (!cbs.data_cb || !cbs.error_cb)
                return false;

            cbs_ = cbs;

            // if (transp->continue_read() != transport::ERROR_OK) return false;

            return true;
        }

        void connection::stop() {
            PUMP_LOCK_SPOINTER(transp, transp_);
            if (transp == nullptr || !transp->is_started())
                return;

            if (!closed_.test_and_set()) {
                // Send close frame
                __send_close_frame();
                // Stop http connection
                transp->stop();
            }
        }

        bool connection::send(c_block_ptr b, uint32 size) {
            PUMP_LOCK_SPOINTER(transp, transp_);
            if (transp == nullptr || !transp->is_started())
                return false;

            frame_header hdr;
            init_frame_header(&hdr, 1, FRAME_OPTCODE_TEXT, has_mask_, mask_key_, size);
            uint32 hdr_size = get_frame_header_size(&hdr);

            // Encode frame header
            std::string buffer(hdr_size, 0);
            if (encode_frame_header(&hdr, (block_ptr)buffer.c_str(), hdr_size) == 0)
                PUMP_ASSERT(false);

            // Append frame payload
            buffer.append(b, size);
            // Make mask payload data if having mask
            if (has_mask_)
                mask_transform((uint8 *)(buffer.data() + hdr_size), size, mask_key_);

            // Send frame buffer
            auto ret = transp->send(buffer.c_str(), (uint32)buffer.size());
            if (ret != transport::ERROR_OK)
                return false;

            return true;
        }

        void connection::on_read(connection_wptr wptr, c_block_ptr b, int32 size) {
            PUMP_LOCK_WPOINTER(conn, wptr);
            if (conn == nullptr)
                return;

            if (!conn->read_cache_.empty()) {
                conn->read_cache_.append(b, size);
                b = conn->read_cache_.data();
                size = (int32)conn->read_cache_.size();
            }

            int32 used_size = conn->__handle_frame(b, size);
            if (used_size < 0) {
                conn->transp_->stop();
                return;
            }

            if (conn->read_cache_.empty()) {
                if (size > used_size)
                    conn->read_cache_.append(b + used_size, size - used_size);
            } else {
                conn->read_cache_ = conn->read_cache_.substr(used_size);
            }
        }

        void connection::on_disconnected(connection_wptr wptr) {
            PUMP_LOCK_WPOINTER(conn, wptr);
            if (conn == nullptr)
                return;

            if (!conn->closed_.test_and_set())
                conn->cbs_.error_cb("websocket connection disconnected");
        }

        void connection::on_stopped(connection_wptr wptr) {
            PUMP_LOCK_WPOINTER(conn, wptr);
            if (conn == nullptr)
                return;

            if (!conn->closed_.test_and_set())
                conn->cbs_.error_cb("websocket connection stopped");
        }

        int32 connection::__handle_frame(c_block_ptr b, uint32 size) {
            int32 hdr_size = 0;
            uint32 payload_size = 0;

            if (decode_phase_ == DECODE_FRAME_HEADER) {
                hdr_size = decode_frame_header(b, size, &decode_hdr_);
                if (hdr_size <= 0)
                    return hdr_size;

                decode_phase_ = DECODE_FRAME_PAYLOAD;
            }

            if (decode_phase_ == DECODE_FRAME_PAYLOAD) {
                payload_size = decode_hdr_.payload_len;
                if (payload_size > 126)
                    payload_size = (uint32)decode_hdr_.ex_payload_len;

                if (hdr_size + payload_size > size)
                    return hdr_size;

                decode_phase_ = DECODE_FRAME_HEADER;

                if (payload_size > 0 && decode_hdr_.mask == 1)
                    mask_transform(
                        (uint8_ptr)(b + hdr_size), payload_size, decode_hdr_.mask_key);

                uint32 optcode = decode_hdr_.optcode;
                if (optcode == FRAME_OPTCODE_SEQUEL || optcode == FRAME_OPTCODE_TEXT ||
                    optcode == FRAME_OPTCODE_BINARY) {
                    cbs_.data_cb(b + hdr_size, payload_size, decode_hdr_.fin == 1);
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
            }

            return int32(hdr_size + payload_size);
        }

        void connection::__send_ping_frame() {
            frame_header hdr;
            init_frame_header(&hdr, 1, FRAME_OPTCODE_PING, 0, 0, 0);
            uint32 hdr_size = get_frame_header_size(&hdr);

            std::string buffer(hdr_size, 0);
            if (encode_frame_header(&hdr, (block_ptr)buffer.c_str(), hdr_size) == 0)
                PUMP_ASSERT(false);

            transp_->send(buffer.c_str(), (uint32)buffer.size());
        }

        void connection::__send_pong_frame() {
            frame_header hdr;
            init_frame_header(&hdr, 1, FRAME_OPTCODE_PONG, 0, 0, 0);
            uint32 hdr_size = get_frame_header_size(&hdr);

            std::string buffer(hdr_size, 0);
            if (encode_frame_header(&hdr, (block_ptr)buffer.c_str(), hdr_size) == 0)
                PUMP_ASSERT(false);

            transp_->send(buffer.c_str(), (uint32)buffer.size());
        }

        void connection::__send_close_frame() {
            frame_header hdr;
            init_frame_header(&hdr, 1, FRAME_OPTCODE_CLOSE, 0, 0, 0);
            uint32 hdr_size = get_frame_header_size(&hdr);

            std::string buffer(hdr_size, 0);
            if (encode_frame_header(&hdr, (block_ptr)buffer.c_str(), hdr_size) == 0)
                PUMP_ASSERT(false);

            transp_->send(buffer.c_str(), (uint32)buffer.size());
        }

    }  // namespace websocket
}  // namespace protocol
}  // namespace pump
