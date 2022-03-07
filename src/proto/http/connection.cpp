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

const static int32_t state_none = 0x00;
const static int32_t state_started = 0x01;
const static int32_t state_upgraded = 0x02;
const static int32_t state_stopped = 0x04;
const static int32_t state_error = 0x05;

connection::connection(bool server, base_transport_sptr &transp) noexcept :
    state_(state_none),
    cache_(nullptr),
    transp_(transp) {
    // Init connection buffer cache.
    cache_ = toolkit::io_buffer::create();
    if (cache_ == nullptr) {
        pump_err_log("create http connection cache failed");
        pump_abort();
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
        pump_abort_with_log("service or transport invalid");
    }

    if (!cbs.packet_cb || !cbs.error_cb) {
        pump_abort_with_log("http connection callbacks invalid");
    }

    int32_t st = state_none;
    if (!state_.compare_exchange_strong(st, state_started)) {
        pump_warn_log("http connection in wrong status");
        return false;
    }

    pump_assert(!pending_packet_);
    pending_packet_.reset(create_pending_packet_(), object_delete<packet>);
    if (!pending_packet_) {
        pump_warn_log("new http pending packet failed");
        return false;
    }

    http_cbs_ = cbs;

    transport_callbacks tcbs;
    connection_wptr wptr = shared_from_this();
    tcbs.read_cb = pump_bind(&connection::on_read, wptr, _1, _2);
    tcbs.stopped_cb = pump_bind(&connection::on_stopped, wptr);
    tcbs.disconnected_cb = pump_bind(&connection::on_disconnected, wptr);
    if (transp_->start(sv, read_mode_once, tcbs) != error_none) {
        pump_warn_log("start transport failed");
        state_.store(state_error);
        return false;
    }

    return true;
}

bool connection::send(packet *pk) {
    if (!transp_ || !transp_->is_started()) {
        pump_warn_log("transport invalid");
        return false;
    }

    std::string data;
    pk->serialize(data);
    if (transp_->send(data.data(), (uint32_t)data.size()) != error_none) {
        pump_warn_log("transport send data failed");
        return false;
    }

    return true;
}

bool connection::start_websocket(const websocket_callbacks &cbs) {
    int32_t st = state_started;
    if (!state_.compare_exchange_strong(st, state_upgraded)) {
        pump_warn_log("websocket connection in wrong status");
        return false;
    }

    if (!cbs.frame_cb || !cbs.error_cb) {
        pump_warn_log("websocket connection callbacks invalid");
        return false;
    }

    ws_cbs_ = cbs;

    if (!__continue_read()) {
        pump_warn_log("continue reading failed");
        return false;
    }

    return true;
}

bool connection::send(const char *b, int32_t size, bool text) {
    if (!transp_ || !transp_->is_started()) {
        pump_warn_log("transport invalid");
        return false;
    }

    bool ret = false;
    auto iob = toolkit::io_buffer::create(16 + size);

    do {
        // Pack frame header
        uint8_t opt = text ? ws_opt_text : ws_opt_bin;
        frame fm(true, opt, size, ws_mask_key_);
        if (!fm.pack_header(iob)) {
            pump_warn_log("pack websocket frame header failed");
            break;
        }

        // Pack frame payload
        if (!iob->write(b, size)) {
            pump_warn_log("pack websocket frame payload failed");
            break;
        }
        fm.mask_payload((char *)(iob->data() - size));

        if (transp_->send(iob) != error_none) {
            pump_warn_log("transport send data failed");
            break;
        }

        ret = true;

    } while (false);

    iob->unrefer();

    return ret;
}

bool connection::is_upgraded() const {
    return state_.load() == state_upgraded;
}

void connection::on_read(connection_wptr wptr, const char *b, int32_t size) {
    auto conn = wptr.lock();
    if (conn) {
        bool cached = false;
        if (pump_unlikely(conn->cache_->size() > 0)) {
            if (!conn->cache_->write(b, size)) {
                pump_warn_log("cache read data failed");
                conn->stop();
                return;
            }

            cached = true;

            b = conn->cache_->data();
            size = conn->cache_->size();
        }

        int32_t parse_size = -1;
        switch (conn->state_.load()) {
        case state_started:
            parse_size = conn->__handle_http_packet(b, size);
            break;
        case state_upgraded:
            parse_size = conn->__handle_websocket_frame(b, size);
            break;
        default:
            pump_abort();
            break;
        }

        if (parse_size >= 0) {
            if (cached) {
                conn->cache_->shift(parse_size);
            } else if (parse_size < size) {
                conn->cache_->write(b + parse_size, size - parse_size);
            }
        } else {
            pump_warn_log("parse data failed");
            conn->stop();
        }
    }
}

void connection::on_disconnected(connection_wptr wptr) {
    auto conn = wptr.lock();
    if (conn) {
        while (true) {
            int32_t st = conn->state_.load();
            switch (conn->state_) {
            case state_started:
                if (conn->state_.compare_exchange_strong(st, state_error)) {
                    pump_debug_log("http connection disconnected");
                    conn->http_cbs_.error_cb("disconnected");
                    return;
                }
                break;
            case state_upgraded:
                if (conn->state_.compare_exchange_strong(st, state_error)) {
                    pump_debug_log("websocket connection disconnected");
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
            switch (st) {
            case state_started:
                if (conn->state_.compare_exchange_strong(st, state_error)) {
                    pump_debug_log("http connection stopped");
                    conn->http_cbs_.error_cb("stopped");
                    return;
                }
                break;
            case state_upgraded:
                if (conn->state_.compare_exchange_strong(st, state_error)) {
                    pump_debug_log("websocket connection stopped");
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
    if (state_ != state_started) {
        pump_warn_log("http connection in wrong status");
        return false;
    }

    if (pending_packet_ && !pending_packet_->is_parse_finished()) {
        pump_warn_log("http pending packet is parsing");
        return false;
    }

    pending_packet_.reset(create_pending_packet_(), object_delete<packet>);
    if (!pending_packet_) {
        pump_warn_log("new http pending packet object failed");
        return false;
    }

    if (!__continue_read()) {
        pump_warn_log("continue reading failed");
        return false;
    }

    return true;
}

void connection::__init_websocket_mask() {
    uint32_t mask = random();
    ws_mask_key_.assign((char *)&mask, 4);
}

void connection::__send_websocket_ping_frame() {
    frame fm(true, ws_opt_ping, 0);
    auto iob = toolkit::io_buffer::create(16);
    if (fm.pack_header(iob)) {
        transp_->send(iob);
    }
    iob->unrefer();
}

void connection::__send_websocket_pong_frame() {
    frame fm(true, ws_opt_pong, 0);
    auto iob = toolkit::io_buffer::create(16);
    if (fm.pack_header(iob)) {
        transp_->send(iob);
    }
    iob->unrefer();
}

void connection::__send_wbesocket_close_frame() {
    frame fm(true, ws_opt_close, 0);
    auto iob = toolkit::io_buffer::create(16);
    if (fm.pack_header(iob)) {
        transp_->send(iob);
    }
    iob->unrefer();
}

int32_t connection::__handle_http_packet(const char *b, int32_t size) {
    if (!pending_packet_) {
        pump_warn_log("http pending packet invalid");
        return -1;
    }

    int32_t parse_size = pending_packet_->parse(b, size);
    if (pending_packet_->is_parse_finished()) {
        http_cbs_.packet_cb(pending_packet_);
    } else if (!__continue_read()) {
        pump_warn_log("continue reading failed");
        return -1;
    }

    return parse_size;
}

int32_t connection::__handle_websocket_frame(const char *b, int32_t size) {
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
                ws_frame_.mask_payload((char *)iob->data());
            }

            switch (ws_frame_.get_opt()) {
            case ws_opt_slice:
            case ws_opt_text:
            case ws_opt_bin:
                ws_cbs_.frame_cb(
                    iob->data(),
                    ws_frame_.get_payload_length(),
                    ws_frame_.is_fin());
                break;
            case ws_opt_close:
                if (!ws_closed_.test_and_set()) {
                    // Send websocket close frame.
                    __send_wbesocket_close_frame();
                    // Stop websocket connection.
                    stop();
                }
                break;
            case ws_opt_ping:
                __send_websocket_pong_frame();
                break;
            case ws_opt_pong:
                // TODO: do nothing?
                break;
            default:
                pump_warn_log("unknown websocket frame");
                iob->unrefer();
                return -1;
            }

            iob->shift(ws_frame_.get_payload_length());

            ws_frame_.reset();
        }
    } while (false);

    iob->unrefer();

    if (!__continue_read()) {
        pump_warn_log("continue reading failed");
        return -1;
    }

    return size - iob->size();
}

}  // namespace http
}  // namespace proto
}  // namespace pump
