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

#include "pump/protocol/http/request.h"
#include "pump/protocol/http/response.h"
#include "pump/protocol/http/connection.h"

namespace pump {
namespace protocol {
namespace http {

    connection::connection(
        bool server, 
        transport::base_transport_sptr &transp) noexcept
      : cache_(nullptr),
        incoming_pocket_(nullptr),
        transp_(transp) {
        if (server) {
            create_incoming_pocket_ = []() {
                return object_create<request>();
            };
        } else {
            create_incoming_pocket_ = []() {
                return object_create<response>();
            };
        }
    }

    connection::~connection() {
        if (transp_) {
            transp_->force_stop();
        }
        if (cache_ != nullptr) {
            cache_->sub_refence();
        }
    }

    bool connection::start(
        service *sv, 
        const http_callbacks &cbs) {
        PUMP_DEBUG_FAILED(
            sv == nullptr || !transp_, 
            "http::connection: start fialed for service or transport invalid",
            return false);

        PUMP_DEBUG_FAILED(
            !cbs.pocket_cb || !cbs.error_cb, 
            "http::connection: start fialed for callbacks invalid",
            return false);
        http_cbs_ = cbs;

        if (cache_ != nullptr || (cache_ = toolkit::io_buffer::create()) == nullptr) {
            return false;
        }

        transport::transport_callbacks tcbs;
        connection_wptr wptr = shared_from_this();
        tcbs.read_cb = pump_bind(&connection::on_read, wptr, _1, _2);
        tcbs.stopped_cb = pump_bind(&connection::on_stopped, wptr);
        tcbs.disconnected_cb = pump_bind(&connection::on_disconnected, wptr);
        if (transp_->start(sv, transport::READ_MODE_ONCE, tcbs) != transport::ERROR_OK) {
            return false;
        }

        return true;
    }

    void connection::stop() {
        __stop_transport();
    }

    bool connection::read_next_pocket() {
        auto transp = transp_;
        if (transp && transp->read_continue() == transport::ERROR_OK) {
            return true;
        }
        return false;
    }

    bool connection::send(const pocket *pk) {
        auto transp = transp_;
        if (transp) {
            std::string data;
            int32_t size = pk->serialize(data);
            PUMP_ASSERT(size > 0);
            if (transp_->send(data.c_str(), size) == transport::ERROR_OK) {
                return true;
            }
        }
        return false;
    }

    bool connection::send(const body *b) {
        auto transp = transp_;
        if (transp) {
            std::string data;
            int32_t size = b->serialize(data);
            PUMP_ASSERT(size > 0);
            if (transp_->send(data.c_str(), size) == transport::ERROR_OK) {
                return true;
            }
        }
        return false;
    }

    void connection::on_read(
        connection_wptr wptr, 
        const block_t *b, 
        int32_t size) {
        auto conn = wptr.lock();
        if (conn) {
            conn->__handle_http_pocket(b, size);
        }
    }

    void connection::on_disconnected(connection_wptr wptr) {
        auto conn = wptr.lock();
        if (conn && conn->http_cbs_.error_cb) {
            conn->http_cbs_.error_cb("http connection disconnected");
        }
    }

    void connection::on_stopped(connection_wptr wptr) {
        auto conn = wptr.lock();
        if (conn && conn->http_cbs_.error_cb) {
            conn->http_cbs_.error_cb("http connection stopped");
        }
    }

    void connection::__handle_http_pocket(
        const block_t *b, 
        int32_t size) {
        auto pk = incoming_pocket_.get();
        if (pk == nullptr) {
            if((pk = create_incoming_pocket_()) == nullptr) {
                return;
            }
            incoming_pocket_.reset(pk, object_delete<pocket>);
        }

        int32_t parse_size = -1;
        if (cache_->data_size() == 0) {
            parse_size = pk->parse(b, size);
            if (parse_size >= 0 && parse_size < size) {
                cache_->append(b + parse_size, uint32_t(size - parse_size));
            }
        } else {
            cache_->append(b, size);
            parse_size = pk->parse(cache_->data(), (int32_t)cache_->data_size());
            if (parse_size > 0) {
                cache_->shift(parse_size);
            }
        }

        if (parse_size == -1) {
            __stop_transport();
            return;
        }

        if (pk->is_parse_finished()) {
            http_cbs_.pocket_cb(std::move(incoming_pocket_));
        } else {
            transp_->read_continue();
        }
    }

}  // namespace http
}  // namespace protocol
}  // namespace pump
