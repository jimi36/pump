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

#include "pump/protocol/http/ws.h"
#include "pump/protocol/http/request.h"
#include "pump/protocol/http/response.h"
#include "pump/protocol/http/connection.h"

namespace pump {
namespace protocol {
namespace http {

    const static int32_t CONN_ST_NONE      = 0x00;
    const static int32_t CONN_ST_STARTED   = 0x01;
    const static int32_t CONN_ST_UPGRADING = 0x02;
    const static int32_t CONN_ST_UPGRADED  = 0x03;
    const static int32_t CONN_ST_STOPPED   = 0x04;
    const static int32_t CONN_ST_ERROR     = 0x05;

    connection::connection(
        bool server, 
        transport::base_transport_sptr &transp) noexcept
      : status_(CONN_ST_NONE),
        cache_(nullptr),
        incoming_packet_(nullptr),
        transp_(transp) {
        if (server) {
            create_incoming_packet_ = []() {
                return object_create<request>();
            };
        } else {
            create_incoming_packet_ = []() {
                return object_create<response>();
            };
        }

        cache_ = toolkit::io_buffer::create();
        PUMP_DEBUG_FAILED(
            cache_ == nullptr, 
            "http::connection: read failed for creating data cache",
            PUMP_ABORT());
    }

    connection::~connection() {
        if (transp_) {
            transp_->force_stop();
        }
        if (cache_ != nullptr) {
            cache_->sub_refence();
        }
    }

    bool connection::start_http(service *sv, const http_callbacks &cbs) {
        PUMP_DEBUG_FAILED(
            sv == nullptr || !transp_, 
            "http::connection: start http failed for service or transport invalid",
            PUMP_ABORT());

        PUMP_DEBUG_FAILED(
            !cbs.packet_cb || !cbs.error_cb, 
            "http::connection: start http failed for http callbacks invalid",
            PUMP_ABORT());
        http_cbs_ = cbs;

        int32_t st = CONN_ST_NONE;
        PUMP_DEBUG_FAILED(
            status_.compare_exchange_strong(st, CONN_ST_STARTED) == false, 
            "http::connection: start http failed for wrong status",
            return false);

        transport::transport_callbacks tcbs;
        connection_wptr wptr = shared_from_this();
        tcbs.read_cb = pump_bind(&connection::on_read, wptr, _1, _2);
        tcbs.stopped_cb = pump_bind(&connection::on_stopped, wptr);
        tcbs.disconnected_cb = pump_bind(&connection::on_disconnected, wptr);
        if (transp_->start(sv, transport::READ_MODE_ONCE, tcbs) != transport::ERROR_OK) {
            status_.store(CONN_ST_ERROR);
            return false;
        }

        return true;
    }

    void connection::stop() {
        if (transp_) {
            transp_->stop();
        }
    }

    bool connection::upgrading() {
        int32_t st = CONN_ST_STARTED;
        PUMP_DEBUG_FAILED(
            status_.compare_exchange_strong(st, CONN_ST_UPGRADING) == false, 
            "http::connection: can't upgrade for wrong status",
            return false);

        return read_again();
    }

    bool connection::start_websocket(const websocket_callbacks &cbs) {
        int32_t st = CONN_ST_UPGRADING;
        PUMP_DEBUG_FAILED(
            status_.compare_exchange_strong(st, CONN_ST_UPGRADED) == false, 
            "http::connection: start websocket failed for wrong status",
            return false);

        PUMP_DEBUG_FAILED(
            !cbs.frame_cb || !cbs.error_cb, 
            "http::connection: start websocket failed for callbacks invalid",
            PUMP_ABORT());
        ws_cbs_ = cbs;

        return read_again();
    }

    bool connection::read_again() {
        if (!transp_ || transp_->read_continue() != transport::ERROR_OK) {
            return false;
        }
        return true;
    }

    bool connection::send(const block_t *b, int32_t size) {
        if (!transp_ || transp_->send(b, size) != transport::ERROR_OK) {            
            return false;
        }
        return true;
    }

    bool connection::is_upgraded() const {
        return status_.load() == CONN_ST_UPGRADED;
    }

    void connection::on_read(
        connection_wptr wptr, 
        const block_t *b, 
        int32_t size) {
        auto conn = wptr.lock();
        if (conn) {
            bool cached = false;
            if (conn->cache_->size() > 0) {
                PUMP_DEBUG_FAILED(
                    conn->cache_->append(b, size) == false, 
                    "http::connection: read failed for appending data cache",
                    PUMP_ABORT());
                
                cached = true;

                b = conn->cache_->data();
                size = conn->cache_->size();
            }

            //printf("%s", b);

            int32_t parse_size = -1;
            switch (conn->status_)
            {
            case CONN_ST_STARTED:
            case CONN_ST_UPGRADING:
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
                    conn->cache_->append(b + parse_size, size - parse_size);
                }
            } else {
                conn->stop();
            }
        }
    }

    void connection::on_disconnected(connection_wptr wptr) {
        auto conn = wptr.lock();
        if (conn) {
            while (true) {
                int32_t st = conn->status_.load();
                switch (conn->status_)
                {
                case CONN_ST_STARTED:
                case CONN_ST_UPGRADING:
                    if (conn->status_.compare_exchange_strong(st, CONN_ST_ERROR)) {
                        conn->http_cbs_.error_cb("http connection disconnected");
                        return;
                    }
                    break;
                case CONN_ST_UPGRADED:
                    if (conn->status_.compare_exchange_strong(st, CONN_ST_ERROR)) {
                        conn->ws_cbs_.error_cb("websocket connection disconnected");
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
                int32_t st = conn->status_.load();
                switch (st)
                {
                case CONN_ST_STARTED:
                case CONN_ST_UPGRADING:
                    if (conn->status_.compare_exchange_strong(st, CONN_ST_ERROR)) {
                        conn->http_cbs_.error_cb("http connection stopped");
                        return;
                    }
                    break;
                case CONN_ST_UPGRADED:
                    if (conn->status_.compare_exchange_strong(st, CONN_ST_ERROR)) {
                        conn->ws_cbs_.error_cb("websocket connection stopped");
                        return;
                    }
                    break;    
                default:
                    break;
                }
            }
        }
    }

    int32_t connection::__handle_http_packet(const block_t *b, int32_t size) {
        if (!incoming_packet_) {
            incoming_packet_.reset(
                create_incoming_packet_(), 
                object_delete<packet>);
            if (!incoming_packet_) {
                return -1;
            }
        }

        int32_t parse_size = incoming_packet_->parse(b, size);
        if (incoming_packet_->is_parse_finished()) {
            http_cbs_.packet_cb(incoming_packet_);
            incoming_packet_.reset();
        } else {
            transp_->read_continue();
        }

        return parse_size;
    }

    int32_t connection::__handle_websocket_frame(const block_t *b, int32_t size) {
        const static int32_t DECODE_FRAME_HEADER = 0;
        const static int32_t DECODE_FRAME_PAYLOAD = 1;

        int32_t parse_size = 0;

        do {
            if (decode_phase_ == DECODE_FRAME_HEADER) {
                if ((parse_size = decode_ws_frame_header(b, size, &decode_hdr_)) < 0) {
                    PUMP_DEBUG_LOG("http::connection: decode frame header failed");
                    return parse_size;
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
                    mask_transform_ws_payload(
                        (uint8_t*)(b + parse_size), 
                        frame_payload_size, 
                        decode_hdr_.mask_key);
                }

                switch (decode_hdr_.optcode)
                {
                case WS_FOT_SEQUEL:
                case WS_FOT_TEXT:
                case WS_FOT_BINARY:
                    ws_cbs_.frame_cb(
                        b + parse_size, 
                        frame_payload_size, 
                        decode_hdr_.fin == 1);
                    break;
                case WS_FOT_CLOSE:
                    if (!closed_.test_and_set()) {
                        // Send close frame
                        send_wbesocket_close(this);
                        // Tagger error callback
                        ws_cbs_.error_cb("websocket connection closed");
                        // Stop http connection
                        stop();
                    }
                    break;
                case WS_FOT_PING:
                    send_websocket_pong(this);
                    break;
                case WS_FOT_PONG:
                    // TODO: do nothing?
                    break;
                default:
                    PUMP_DEBUG_LOG(
                        "http::connection: handle frame failed for unknown frame");
                    return -1;
                }

                parse_size += frame_payload_size;

                decode_phase_ = DECODE_FRAME_HEADER;
            }
        } while(false);

        transp_->read_continue();

        return parse_size;
    }

    bool send_http_packet(connection_sptr &conn, packet *pk) {
        std::string data;
        pk->serialize(data);
        return conn->send(data.c_str(), (uint32_t)data.size());
    }

    bool send_http_simple_response(
        connection_sptr &conn,
        int32_t status_code,
        const std::string &payload) {
        http::response rsp;
        rsp.set_http_version(http::VERSION_11);
        rsp.set_status_code(status_code);

        if (!payload.empty()) {
            rsp.set_head("Content-Length", (int32_t)payload.size());

            http::body_sptr hb(new http::body);
            hb->append(payload);

            rsp.set_body(hb);
        }

        return send_http_packet(conn, &rsp);
    }

}  // namespace http
}  // namespace protocol
}  // namespace pump
