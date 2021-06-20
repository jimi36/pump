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

#include "pump/transport/flow/flow_tls.h"

namespace pump {
namespace transport {
namespace flow {

    flow_tls::flow_tls() noexcept
      : is_handshaked_(false),
        session_(nullptr),
        send_iob_(nullptr){
    }

    flow_tls::~flow_tls() {
        transport::destory_tls_session(session_);
    }

    error_code flow_tls::init(
        poll::channel_sptr& ch,
        bool client,
        pump_socket fd,
        transport::tls_credentials xcred) {
        PUMP_DEBUG_FAILED(
            !ch, 
            "flow_tls: init failed for channel invalid",
            return ERROR_FAULT);
        ch_ = ch;

        PUMP_DEBUG_FAILED(
            fd < 0, 
            "flow_tls: init failed for fd invalid",
            return ERROR_FAULT);
        fd_ = fd;

        session_ = transport::create_tls_session(
                    client,
                    fd, 
                    xcred);
        if (session_ == nullptr) {
            return ERROR_FAULT;
        }

        return ERROR_OK;
    }

    error_code flow_tls::want_to_send(toolkit::io_buffer *iob) {
        PUMP_DEBUG_FAILED(
            iob == nullptr, 
            "flow_tls: want to send failed for io buffer invalid",
            return ERROR_FAULT);
        send_iob_ = iob;
        
        int32_t size = transport::tls_send(
                        session_, send_iob_->buffer(), 
                        send_iob_->data_size());
        if (PUMP_LIKELY(size > 0)) {
            // Shift send buffer and check data size.
            if (send_iob_->shift(size) > 0) {
                return ERROR_AGAIN;
            }
            send_iob_->reset();
            send_iob_ = nullptr;
            return ERROR_OK;
        } else if (PUMP_UNLIKELY(size < 0)) {
            // Send again
            return ERROR_AGAIN;
        }

        PUMP_DEBUG_LOG("flow_tls: want to send failed");

        return ERROR_FAULT;
    }

    error_code flow_tls::send() {
        PUMP_ASSERT(send_iob_);
        int32_t size = transport::tls_send(
                        session_, 
                        send_iob_->buffer(), 
                        send_iob_->data_size());
        if (PUMP_LIKELY(size > 0)) {
            // Shift send buffer and check data size.
            if (send_iob_->shift(size) > 0) {
                return ERROR_AGAIN;
            }
            send_iob_->reset();
            send_iob_ = nullptr;
            return ERROR_OK;
        } else if (PUMP_UNLIKELY(size < 0)) {
            // Send again
            return ERROR_AGAIN;
        }

        PUMP_DEBUG_LOG("flow_tls: send failed");

        return ERROR_FAULT;
    }

}  // namespace flow
}  // namespace transport
}  // namespace pump
