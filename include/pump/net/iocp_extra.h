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

#ifndef pump_net_iocp_extra_h
#define pump_net_iocp_extra_h

#include "pump/types.h"
#include "pump/config.h"
#include "pump/net/socket.h"

namespace pump {
namespace net {

#if defined(PUMP_HAVE_IOCP)
    /*********************************************************************************
     * New iocp extra function
     ********************************************************************************/
    void_ptr new_iocp_extra_function(int32_t fd);

    /*********************************************************************************
     * Delete iocp extra function
     ********************************************************************************/
    void delete_iocp_extra_function(void_ptr fns);

    /*********************************************************************************
     * Get LPFN_ACCEPTEX function
     ********************************************************************************/
    void_ptr get_iocp_accpet_fn(void_ptr fns);

    /*********************************************************************************
     * Get LPFN_GETACCEPTEXSOCKADDRS function
     ********************************************************************************/
    void_ptr get_accept_addrs_fn(void_ptr fns);

    /*********************************************************************************
     * Get LPFN_CONNECTEX function
     ********************************************************************************/
    void_ptr get_iocp_connect_fn(void_ptr fns);
#endif

}  // namespace net
}  // namespace pump

#endif