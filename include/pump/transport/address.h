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
#include "pump/memory.h"
#include "pump/net/socket.h"

namespace pump {
namespace transport {

// Max address length
const static int32_t max_address_len = 64;

class pump_lib address {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    address() pump_noexcept;
    address(const std::string &ip, uint16_t port);
    address(const struct sockaddr *addr, int32_t addrlen);

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~address() = default;

    /*********************************************************************************
     * Set and Get address
     ********************************************************************************/
    bool set(const std::string &ip, uint16_t port);
    bool set(const struct sockaddr *addr, int32_t addrlen);

    /*********************************************************************************
     * Get address struct
     ********************************************************************************/
    pump_inline struct sockaddr *get() pump_noexcept {
        return (struct sockaddr *)addr_;
    }
    pump_inline const struct sockaddr *get() const pump_noexcept {
        return (const struct sockaddr *)addr_;
    }

    /*********************************************************************************
     * Get port
     ********************************************************************************/
    uint16_t port() const;

    /*********************************************************************************
     * Get ip
     ********************************************************************************/
    std::string ip() const;

    /*********************************************************************************
     * Set and Get address struct size
     ********************************************************************************/
    pump_inline int32_t len() const pump_noexcept {
        return addrlen_;
    }

    /*********************************************************************************
     * Is ipv6 or not
     ********************************************************************************/
    pump_inline bool is_ipv6() const pump_noexcept {
        return is_v6_;
    }

    /*********************************************************************************
     * Address to string
     ********************************************************************************/
    std::string to_string() const;

    /*********************************************************************************
     * Operator ==
     ********************************************************************************/
    bool operator==(const address &other) const pump_noexcept;

    /*********************************************************************************
     * Operator <
     ********************************************************************************/
    bool operator<(const address &other) const pump_noexcept;

  private:
    bool is_v6_;

    int32_t addrlen_;
    char addr_[max_address_len];
};
DEFINE_SMART_POINTERS(address);

}  // namespace transport
}  // namespace pump

#endif
