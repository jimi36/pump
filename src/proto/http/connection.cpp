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

using transport::error_none;
using transport::read_mode_once;
using transport::transport_callbacks;

connection::connection(bool server, base_transport_sptr &transp)
  : state_(state_none),
    cache_(nullptr),
    transp_(transp) {
    if (server) {
        create_pending_packet_ = []() {
            return pump_object_create<request>();
        };
    } else {
        create_pending_packet_ = []() {
            return pump_object_create<response>();
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
    if (sv == nullptr) {
        pump_debug_log("service invalid");
        return false;
    }

    if (!cbs.packet_cb ||
        !cbs.error_cb) {
        pump_debug_log("http callbacks invalid");
        return false;
    }

    if (!transp_) {
        pump_debug_log("connection transport invalid");
        return false;
    }

    int32_t st = state_none;
    if (!state_.compare_exchange_strong(st, state_started)) {
        pump_debug_log("http connection in wrong state");
        return false;
    }

    http_cbs_ = cbs;

    transport_callbacks tcbs;
    connection_wptr wptr = shared_from_this();
    tcbs.read_cb = pump_bind(&connection::on_read, wptr, _1, _2);
    tcbs.stopped_cb = pump_bind(&connection::on_stopped, wptr);
    tcbs.disconnected_cb = pump_bind(&connection::on_disconnected, wptr);
    if (transp_->start(sv, read_mode_once, tcbs) != error_none) {
        pump_debug_log("start connection transport failed");
        state_.store(state_error);
        return false;
    }

    return true;
}

bool connection::send(packet *pk) {
    if (!transp_ || !transp_->is_started()) {
        pump_debug_log("connection transport invalid");
        return false;
    }

    std::string data;
    pk->serialize(data);
    if (transp_->send(data.data(), (uint32_t)data.size()) != error_none) {
        pump_debug_log("connection transport send http packet failed");
        return false;
    }

    return true;
}

bool connection::start_websocket(const websocket_callbacks &cbs) {
    auto st = state_started;
    if (!state_.compare_exchange_strong(st, state_upgraded)) {
        pump_debug_log("connection in wrong state");
        return false;
    }

    if (!cbs.frame_cb ||
        !cbs.error_cb) {
        pump_debug_log("websocket callbacks invalid");
        return false;
    }

    ws_cbs_ = cbs;

    if (!__async_read()) {
        pump_debug_log("async read failed");
        return false;
    }

    return true;
}

bool connection::send(const char *b, int32_t size, bool text) {
    if (!transp_ || !transp_->is_started()) {
        pump_debug_log("connection transport invalid");
        return false;
    }

    bool ret = false;
    toolkit::io_buffer *iob = nullptr;
    do {
        iob = toolkit::io_buffer::create(16 + size);
        if (iob == nullptr) {
            pump_warn_log("new iob object failed");
            break;
        }

        uint8_t opt = text ? wscode_text : wscode_bin;
        frame_header wf(true, opt, size, ws_key_);
        if (!wf.pack_header(iob)) {
            pump_debug_log("pack websocket frame header failed");
            break;
        }

        if (!iob->write(b, size)) {
            pump_debug_log("pack websocket frame payload failed");
            break;
        }

        wf.mask_payload((char *)(iob->data() - size));

        if (transp_->send(iob) != error_none) {
            pump_debug_log("connection transport send failed");
            break;
        }

        ret = true;
    } while (false);

    if (iob != nullptr) {
        iob->unrefer();
    }

    return ret;
}

void connection::on_read(
    connection_wptr conn,
    const char *b,
    int32_t size) {
    auto conn_locker = conn.lock();
    if (conn_locker) {
        int32_t parse_size = -1;
        do {
            if (conn_locker->cache_ == nullptr) {
                conn_locker->cache_ = toolkit::io_buffer::create();
                if (conn_locker->cache_ == nullptr) {
                    pump_warn_log("create cache failed");
                    break;
                }
            }

            bool cached = false;
            if (conn_locker->cache_->size() > 0) {
                cached = true;
                if (!conn_locker->cache_->write(b, size)) {
                    pump_debug_log("write data to cache failed");
                    break;
                }
                b = conn_locker->cache_->data();
                size = conn_locker->cache_->size();
            }

            switch (conn_locker->state_.load()) {
            case state_started:
                parse_size = conn_locker->__handle_http_packet(b, size);
                break;
            case state_upgraded:
                parse_size = conn_locker->__handle_websocket_frame(b, size);
                break;
            default:
                pump_debug_log("connection in wrong state");
                break;
            }
            if (parse_size == -1) {
                pump_debug_log("parse data failed");
                break;
            }

            if (cached) {
                conn_locker->cache_->shift(parse_size);
            } else if (parse_size < size) {
                conn_locker->cache_->write(b + parse_size, size - parse_size);
            }
        } while (false);

        if (parse_size == -1) {
            conn_locker->stop();
        }
    }
}

void connection::on_disconnected(connection_wptr conn) {
    auto conn_locker = conn.lock();
    if (conn_locker) {
        while (true) {
            int32_t st = conn_locker->state_.load();
            switch (conn_locker->state_) {
            case state_started:
                if (conn_locker->state_.compare_exchange_strong(st, state_error)) {
                    pump_debug_log("http connection disconnected");
                    conn_locker->http_cbs_.error_cb("disconnected");
                    return;
                }
                break;
            case state_upgraded:
                if (conn_locker->state_.compare_exchange_strong(st, state_error)) {
                    pump_debug_log("websocket connection disconnected");
                    if (conn_locker->ws_closed_.test_and_set()) {
                        conn_locker->ws_cbs_.error_cb("closed");
                    } else {
                        conn_locker->ws_cbs_.error_cb("disconnected");
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

void connection::on_stopped(connection_wptr conn) {
    auto conn_locker = conn.lock();
    if (conn_locker) {
        while (true) {
            int32_t st = conn_locker->state_.load();
            switch (st) {
            case state_started:
                if (conn_locker->state_.compare_exchange_strong(st, state_error)) {
                    pump_debug_log("http connection stopped");
                    conn_locker->http_cbs_.error_cb("stopped");
                    return;
                }
                break;
            case state_upgraded:
                if (conn_locker->state_.compare_exchange_strong(st, state_error)) {
                    pump_debug_log("websocket connection stopped");
                    if (conn_locker->ws_closed_.test_and_set()) {
                        conn_locker->ws_cbs_.error_cb("closed");
                    } else {
                        conn_locker->ws_cbs_.error_cb("stopped");
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

bool connection::__async_read_http_packet() {
    if (state_ != state_started) {
        pump_debug_log("http connection in wrong state");
        return false;
    }

    if (pending_packet_ && !pending_packet_->is_parse_finished()) {
        pump_debug_log("http pending packet in parsing");
        return false;
    }

    pending_packet_.reset(create_pending_packet_(), pump_object_destroy<packet>);
    if (!pending_packet_) {
        pump_debug_log("new http pending packet object failed");
        return false;
    }

    if (!__async_read()) {
        pump_debug_log("async read failed");
        return false;
    }

    return true;
}

void connection::__init_websocket_key() {
    auto key = random();
    ws_key_.assign((char *)&key, 4);
}

void connection::__send_websocket_ping_frame() {
    frame_header fm(true, wscode_ping, 0);
    auto iob = toolkit::io_buffer::create(16);
    if (fm.pack_header(iob)) {
        transp_->send(iob);
    }
    iob->unrefer();
}

void connection::__send_websocket_pong_frame() {
    frame_header fm(true, wscode_pong, 0);
    auto iob = toolkit::io_buffer::create(16);
    if (fm.pack_header(iob)) {
        transp_->send(iob);
    }
    iob->unrefer();
}

void connection::__send_wbesocket_close_frame() {
    frame_header fm(true, wscode_close, 0);
    auto iob = toolkit::io_buffer::create(16);
    if (fm.pack_header(iob)) {
        transp_->send(iob);
    }
    iob->unrefer();
}

int32_t connection::__handle_http_packet(const char *b, int32_t size) {
    if (!pending_packet_) {
        pump_debug_log("http pending packet invalid");
        return -1;
    }

    auto parse_size = pending_packet_->parse(b, size);
    if (pending_packet_->is_parse_finished()) {
        http_cbs_.packet_cb(pending_packet_);
    } else if (!__async_read()) {
        pump_debug_log("async read failed");
        return -1;
    }

    return parse_size;
}

int32_t connection::__handle_websocket_frame(const char *b, int32_t size) {
    auto iob = toolkit::io_buffer::create_by_reference(b, size);

    do {
        // Decode websocket frame header.
        if (!ws_frame_.is_unpacked()) {
            if (!ws_frame_.unpack_header(iob)) {
                break;
            }
        }

        if (ws_frame_.is_unpacked()) {
            // Decode websocket frame payload.
            if (ws_frame_.get_payload_length() > iob->size()) {
                break;
            }
            if (ws_frame_.get_payload_length() > 0) {
                ws_frame_.mask_payload((char *)iob->data());
            }

            switch (ws_frame_.get_code()) {
            case wscode_slice:
            case wscode_text:
            case wscode_bin:
                ws_cbs_.frame_cb(
                    iob->data(),
                    ws_frame_.get_payload_length(),
                    ws_frame_.is_fin());
                break;
            case wscode_close:
                if (!ws_closed_.test_and_set()) {
                    __send_wbesocket_close_frame();
                    stop();
                }
                break;
            case wscode_ping:
                __send_websocket_pong_frame();
                break;
            case wscode_pong:
                // TODO: do nothing?
                break;
            default:
                pump_debug_log("unknown websocket frame");
                iob->unrefer();
                return -1;
            }

            iob->shift(ws_frame_.get_payload_length());

            ws_frame_.reset();
        }
    } while (false);

    iob->unrefer();

    if (!__async_read()) {
        pump_debug_log("async read failed");
        return -1;
    }

    return size - iob->size();
}

}  // namespace http
}  // namespace proto
}  // namespace pump
