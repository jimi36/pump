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

#ifndef pump_proto_http_uri_h
#define pump_proto_http_uri_h

#include <map>

#include "pump/proto/http/utils.h"
#include "pump/transport/address.h"

namespace pump {
namespace proto {
namespace http {

using transport::address;

typedef std::string uri_type;
const static uri_type uri_http = "http";
const static uri_type uri_https = "https";
const static uri_type uri_ws = "ws";
const static uri_type uri_wss = "wss";
const static uri_type uri_end = "";

class pump_lib uri {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    uri() noexcept;
    uri(const std::string &url) noexcept;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~uri() = default;

    /*********************************************************************************
     * Reset uri
     ********************************************************************************/
    void reset();

    /*********************************************************************************
     * Parse url
     ********************************************************************************/
    bool parse(const std::string &url);

    /*********************************************************************************
     * Set uri type
     ********************************************************************************/
    pump_inline void set_proto(uri_type proto) {
        tp_ = proto;
    }

    /*********************************************************************************
     * Get uri type
     ********************************************************************************/
    pump_inline uri_type get_type() const {
        return tp_;
    }

    /*********************************************************************************
     * Set host
     ********************************************************************************/
    pump_inline void set_host(const std::string &host) {
        host_ = host;
    }

    /*********************************************************************************
     * Get host
     ********************************************************************************/
    pump_inline const std::string &get_host() const {
        return host_;
    }

    /*********************************************************************************
     * Set path
     ********************************************************************************/
    pump_inline void set_path(const std::string &path) {
        path_ = path;
    }

    /*********************************************************************************
     * Get path
     ********************************************************************************/
    pump_inline const std::string &get_path() const {
        return path_;
    }

    /*********************************************************************************
     * Set param
     ********************************************************************************/
    pump_inline void set_param(
        const std::string &key,
        const std::string &value) {
        params_[key] = value;
    }

    /*********************************************************************************
     * Get param
     ********************************************************************************/
    bool get_param(const std::string &key, std::string &value) const;

    /*********************************************************************************
     * To url string
     ********************************************************************************/
    std::string to_url() const;

    /*********************************************************************************
     * To address
     ********************************************************************************/
    address to_address() const;

  private:
    // Uri type
    uri_type tp_;
    // Uri host
    std::string host_;
    // Uri path
    std::string path_;
    // Uri params
    std::map<std::string, std::string> params_;
};
DEFINE_SMART_POINTERS(uri);

}  // namespace http
}  // namespace proto
}  // namespace pump

#endif