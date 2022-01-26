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

#include "pump/proto/http/request.h"
#include "pump/proto/http/response.h"
#include "pump/proto/http/connection.h"

namespace pump {
namespace proto {
namespace http {

    using transport::ERROR_OK;
    using transport::READ_MODE_ONCE;
    using transport::transport_callbacks;

    const static int32_t CONN_ST_NONE      = 0x00;
    const static int32_t CONN_ST_STARTED   = 0x01;
    const static int32_t CONN_ST_UPGRADED  = 0x02;
    const static int32_t CONN_ST_STOPPED   = 0x04;
    const static int32_t CONN_ST_ERROR     = 0x05;

    connection::connection(bool server, base_transport_sptr &transp) noexcept
      : state_(CONN_ST_NONE),
        cache_(nullptr),
        transp_(transp) {
        // Init connection buffer cache.
        cache_ = toolkit::io_buffer::create();
        if (cache_ == nullptr) {
            PUMP_ERR_LOG("create http connection cache failed");
            PUMP_ABORT();
        }

        if (server) {
            create_pending_packet_ = []() {
                return object_create<request>();
            };
        } else {
            create_pending_packet_ = []() {
                return object_create<response>();
            };
        }
    }

    connection::~connection() {
        if (transp_) {
            transp_->force_stop();
        }
        if (cache_ != nullptr) {
            cache_->unrefer();
        }
    }

    void connection::stop() {
        if (transp_) {
            transp_->stop();
        }
    }

    bool connection::start_http(service *sv, const http_callbacks &cbs) {
        if (sv == nullptr || !transp_) {
            PUMP_WARN_LOG("service or transport invalid");
            PUMP_ABORT();
        }

        if (!cbs.packet_cb || !cbs.error_cb) {
            PUMP_WARN_LOG("http connection callbacks invalid");
            PUMP_ABORT();
        }

        int32_t st = CONN_ST_NONE;
        if (!state_.compare_exchange_strong(st, CONN_ST_STARTED)) {
            PUMP_WARN_LOG("http connection in wrong status");
            return false;
        }

        PUMP_ASSERT(!pending_packet_);
        pending_packet_.reset(create_pending_packet_(), object_delete<packet>);
        if (!pending_packet_) {
            PUMP_WARN_LOG("new http pending packet failed");
            return false;
        }

        http_cbs_ = cbs;

        transport_callbacks tcbs;
        connection_wptr wptr = shared_from_this();
        tcbs.read_cb = pump_bind(&connection::on_read, wptr, _1, _2);
        tcbs.stopped_cb = pump_bind(&connection::on_stopped, wptr);
        tcbs.disconnected_cb = pump_bind(&connection::on_disconnected, wptr);
        if (transp_->start(sv, READ_MODE_ONCE, tcbs) != ERROR_OK) {
            PUMP_WARN_LOG("start transport failed");
            state_.store(CONN_ST_ERROR);
            return false;
        }

        return true;
    }

    bool connection::send(packet *pk) {
        if (!transp_ || !transp_->is_started()) {
            PUMP_WARN_LOG("transport invalid");
            return false;
        }

        std::string data;
        pk->serialize(data);
        if (transp_->send(data.data(), (uint32_t)data.size()) != ERROR_OK) {
            PUMP_WARN_LOG("transport send data failed");
            return false;
        }

        return true;
    }

    bool connection::start_websocket(const websocket_callbacks &cbs) {
        int32_t st = CONN_ST_STARTED;
        if (!state_.compare_exchange_strong(st, CONN_ST_UPGRADED)) { 
            PUMP_WARN_LOG("websocket connection in wrong status");
            return false;
        }

        if (!cbs.frame_cb || !cbs.error_cb) {
            PUMP_WARN_LOG("websocket connection callbacks invalid");
            return false;
        }

        ws_cbs_ = cbs;

        if (!__continue_read()) {
            PUMP_WARN_LOG("continue reading failed");
            return false;
        }

        return true;
    }

    bool connection::send(const block_t *b, int32_t size, bool text) {
        if (!transp_ || !transp_->is_started()) {
            PUMP_WARN_LOG("transport invalid");
            return false;
        }

        bool ret = false;
        auto iob = toolkit::io_buffer::create(16 + size);

        do {
            // Pack frame header
            uint8_t opt = text ? WS_OPT_TEXT : WS_OPT_BIN;
            frame fm(true, opt, size, ws_mask_key_);
            if (!fm.pack_header(iob)) {
                PUMP_WARN_LOG("pack websocket frame header failed");
                break;
            }

            // Pack frame payload
            if (!iob->write(b, size)) {
                PUMP_WARN_LOG("pack websocket frame payload failed");
                break;
            }
            fm.mask_payload((uint8_t*)(iob->data() - size));

            if (transp_->send(iob) != ERROR_OK) {
                PUMP_WARN_LOG("transport send data failed");
                break;
            }

            ret = true;

        } while (false);

        iob->unrefer();

        return ret;
    }

    bool connection::is_upgraded() const {
        return state_.load() == CONN_ST_UPGRADED;
    }

    void connection::on_read(
        connection_wptr wptr, 
        const block_t *b, 
        int32_t size) {
        auto conn = wptr.lock();
        if (conn) {
            bool cached = false;
            if (PUMP_UNLIKELY(conn->cache_->size() > 0)) {
                if(!conn->cache_->write(b, size)) { 
                    PUMP_WARN_LOG("cache read data failed");
                    conn->stop();
                    return;
                }
                
                cached = true;

                b = conn->cache_->data();
                size = conn->cache_->size();
            }

            int32_t parse_size = -1;
            switch (conn->state_.load())
            {
            case CONN_ST_STARTED:
                parse_size = conn->__handle_http_packet(b, size);
                break;
            case CONN_ST_UPGRADED:
                parse_size = conn->__handle_websocket_frame(b, size);
                break;
            default:
                PUMP_ABORT();
                break;
            }

            if (parse_size >= 0) {
                if (cached) {
                    conn->cache_->shift(parse_size);
                } else if (parse_size < size) {
                    conn->cache_->write(b + parse_size, size - parse_size);
                }
            } else {
                PUMP_WARN_LOG("parse data failed");
                conn->stop();
            }
        }
    }

    void connection::on_disconnected(connection_wptr wptr) {
        auto conn = wptr.lock();
        if (conn) {
            while (true) {
                int32_t st = conn->state_.load();
                switch (conn->state_)
                {
                case CONN_ST_STARTED:
                    if (conn->state_.compare_exchange_strong(st, CONN_ST_ERROR)) {
                        PUMP_DEBUG_LOG("http connection disconnected");
                        conn->http_cbs_.error_cb("disconnected");
                        return;
                    }
                    break;
                case CONN_ST_UPGRADED:
                    if (conn->state_.compare_exchange_strong(st, CONN_ST_ERROR)) {
                        PUMP_DEBUG_LOG("websocket connection disconnected");
                        if (conn->ws_closed_.test_and_set()) {
                            conn->ws_cbs_.error_cb("closed");
                        } else {
                            conn->ws_cbs_.error_cb("disconnected");
                        }
                        return;
                    }
                    break;    
                default:
                    return;
                }
            }
        }
    }

    void connection::on_stopped(connection_wptr wptr) {
        auto conn = wptr.lock();
        if (conn) {
            while (true) {
                int32_t st = conn->state_.load();
                switch (st)
                {
                case CONN_ST_STARTED:
                    if (conn->state_.compare_exchange_strong(st, CONN_ST_ERROR)) {
                        PUMP_DEBUG_LOG("http connection stopped");
                        conn->http_cbs_.error_cb("stopped");
                        return;
                    }
                    break;
                case CONN_ST_UPGRADED:
                    if (conn->state_.compare_exchange_strong(st, CONN_ST_ERROR)) {
                        PUMP_DEBUG_LOG("websocket connection stopped");
                        if (conn->ws_closed_.test_and_set()) {
                            conn->ws_cbs_.error_cb("closed");
                        } else {
                            conn->ws_cbs_.error_cb("stopped");
                        }
                        return;
                    }
                    break;    
                default:
                    return;
                }
            }
        }
    }

    bool connection::__read_next_http_packet() {
        if (state_ != CONN_ST_STARTED) {
            PUMP_WARN_LOG("http connection in wrong status");
            return false;
        }

        if (pending_packet_ && !pending_packet_->is_parse_finished()) {
            PUMP_WARN_LOG("http pending packet is parsing");
            return false;
        }

        pending_packet_.reset(create_pending_packet_(), object_delete<packet>);
        if (!pending_packet_) {
            PUMP_WARN_LOG("new http pending packet object failed");
            return false;
        }

        if (!__continue_read()) {
            PUMP_WARN_LOG("continue reading failed");
            return false;
        }

        return true;
    }

    void connection::__init_websocket_mask() {        
        uint32_t mask = random();
        ws_mask_key_.assign((block_t*)&mask, 4);
    }

    void connection::__send_websocket_ping_frame() {
        frame fm(true, WS_OPT_PING, 0);
        auto iob = toolkit::io_buffer::create(16);
        if (fm.pack_header(iob)) {
            transp_->send(iob);
        }
        iob->unrefer();
    }

    void connection::__send_websocket_pong_frame() {
        frame fm(true, WS_OPT_PONG, 0);
        auto iob = toolkit::io_buffer::create(16);
        if (fm.pack_header(iob)) {
            transp_->send(iob);
        }
        iob->unrefer();
    }

    void connection::__send_wbesocket_close_frame() {
        frame fm(true, WS_OPT_CLOSE, 0);
        auto iob = toolkit::io_buffer::create(16);
        if (fm.pack_header(iob)) {
            transp_->send(iob);
        }
        iob->unrefer();
    }

    int32_t connection::__handle_http_packet(const block_t *b, int32_t size) {
        if (!pending_packet_) {
            PUMP_WARN_LOG("http pending packet invalid");
            return -1;
        }

        int32_t parse_size = pending_packet_->parse(b, size);
        if (pending_packet_->is_parse_finished()) {
            http_cbs_.packet_cb(pending_packet_);
        } else if (!__continue_read()) {
            PUMP_WARN_LOG("continue reading failed");
            return -1;
        }

        return parse_size;
    }

    int32_t connection::__handle_websocket_frame(const block_t *b, int32_t size) {
        auto iob = toolkit::io_buffer::create_by_refence(b, size);

        do {
            // Decode websocket frame header.
            if (!ws_frame_.is_header_unpacked()) { 
                if (!ws_frame_.unpack_header(iob)) {
                    break;
                }
            }

            if (ws_frame_.is_header_unpacked()) {
                // Decode websocket frame payload.
                if (ws_frame_.get_payload_length() > iob->size()) {
                    break;
                }
                if (ws_frame_.get_payload_length() > 0) {
                    ws_frame_.mask_payload((uint8_t*)iob->data());
                }

                switch (ws_frame_.get_opt())
                {
                case WS_OPT_SLICE:
                case WS_OPT_TEXT:
                case WS_OPT_BIN:
                    ws_cbs_.frame_cb(
                        iob->data(), 
                        ws_frame_.get_payload_length(), 
                        ws_frame_.is_fin());
                    break;
                case WS_OPT_CLOSE:
                    if (!ws_closed_.test_and_set()) {
                        // Send websocket close frame.
                        __send_wbesocket_close_frame();
                        // Stop websocket connection.
                        stop();
                    }
                    break;
                case WS_OPT_PING:
                    __send_websocket_pong_frame();
                    break;
                case WS_OPT_PONG:
                    // TODO: do nothing?
                    break;
                default:
                    PUMP_WARN_LOG("unknown websocket frame");
                    iob->unrefer();
                    return -1;
                }

                iob->shift(ws_frame_.get_payload_length());

                ws_frame_.reset();
            }
        } while(false);

        iob->unrefer();

        if (!__continue_read()) {
            PUMP_WARN_LOG("continue reading failed");
            return -1;
        }

        return size - iob->size();
    }

}  // namespace http
}  // namespace proto
}  // namespace pump
