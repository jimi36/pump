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

#ifndef pump_transport_address_h
#define pump_transport_address_h

#include <string>

#include "pump/utils.h"
#include "pump/net/socket.h"

namespace pump {
namespace transport {

#define ADDRESS_MAX_LEN 64

    class LIB_PUMP address {
      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        address() noexcept;
        address(const std::string &ip, uint16 port);
        address(const struct sockaddr *addr, int32 addrlen);

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~address() = default;

        /*********************************************************************************
         * Set and Get address
         ********************************************************************************/
        bool set(const std::string &ip, uint16 port);
        bool set(const struct sockaddr *addr, int32 addrlen);

        /*********************************************************************************
         * Get address struct
         ********************************************************************************/
        PUMP_INLINE struct sockaddr *get() {
            return (struct sockaddr *)addr_;
        }
        PUMP_INLINE const struct sockaddr *get() const {
            return (const struct sockaddr *)addr_;
        }

        /*********************************************************************************
         * Set and Get address struct size
         ********************************************************************************/
        PUMP_INLINE int32 len() const {
            return addrlen_;
        }

        /*********************************************************************************
         * Get port
         ********************************************************************************/
        PUMP_INLINE uint16 port() const {
            return port_;
        }

        /*********************************************************************************
         * Get ip
         ********************************************************************************/
        PUMP_INLINE const std::string &ip() const {
            return ip_;
        }

        /*********************************************************************************
         * Is ipv6 or not
         ********************************************************************************/
        PUMP_INLINE bool is_ipv6() const {
            return is_v6_;
        }

        /*********************************************************************************
         * Address to string
         ********************************************************************************/
        std::string to_string() const;

        /*********************************************************************************
         * Operator ==
         ********************************************************************************/
        bool operator==(const address &other) const noexcept;

        /*********************************************************************************
         * Operator <
         ********************************************************************************/
        bool operator<(const address &other) const noexcept;

      private:
        /*********************************************************************************
         * Update ip and port
         ********************************************************************************/
        void __update();

      private:
        bool is_v6_;
        int32 addrlen_;
        block addr_[ADDRESS_MAX_LEN];

        std::string ip_;
        uint16 port_;
    };
    DEFINE_ALL_POINTER_TYPE(address);

}  // namespace transport
}  // namespace pump

#endif
