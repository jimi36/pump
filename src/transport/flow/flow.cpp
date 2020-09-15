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

#include "pump/transport/flow/flow.h"

namespace pump {
namespace transport {
    namespace flow {

        flow_base::flow_base() noexcept : fd_(-1), extra_fns_(nullptr) {
        }

        int32 flow_base::unbind() {
            int32 fd = fd_;
            fd_ = -1;
            return fd;
        }

        void flow_base::shutdown() {
            if (fd_ > 0) {
                net::shutdown(fd_);
            }
        }

        void flow_base::close() {
#if defined(PUMP_HAVE_IOCP)
            if (extra_fns_) {
                net::delete_iocp_extra_function(extra_fns_);
                extra_fns_ = nullptr;
            }
#endif
            if (fd_ > 0) {
                net::close(fd_);
                fd_ = -1;
            }
        }

    }  // namespace flow
}  // namespace transport
}  // namespace pump