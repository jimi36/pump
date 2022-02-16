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

#ifndef pump_proto_http_header_h
#define pump_proto_http_header_h

#include <map>

#include "pump/proto/http/utils.h"

namespace pump {
namespace proto {
namespace http {

class pump_lib header {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    header() noexcept;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~header() = default;

    /*********************************************************************************
     * Set http head by append
     ********************************************************************************/
    void set_head(const std::string &name, int32_t value);
    void set_head(const std::string &name, const std::string &value);

    /*********************************************************************************
     * Set http header by replace
     ********************************************************************************/
    void set_unique_head(const std::string &name, int32_t value);
    void set_unique_head(const std::string &name, const std::string &value);

    /*********************************************************************************
     * Get http header
     ********************************************************************************/
    bool get_head(const std::string &name, int32_t &value) const;
    bool get_head(const std::string &name, std::string &value) const;
    bool get_head(const std::string &name,
                  std::vector<std::string> &values) const;

    /*********************************************************************************
     * Check header field existed or not
     ********************************************************************************/
    bool has_head(const std::string &name) const;

  protected:
    /*********************************************************************************
     * Parse heads
     * This parse http header and return parsed size.
     * If parsed error, return -1.
     ********************************************************************************/
    int32_t __parse_header(const char *b, int32_t size);

    /*********************************************************************************
     * Check parse is finished or not
     ********************************************************************************/
    pump_inline bool __is_header_parsed() const {
        return header_parsed_;
    }

    /*********************************************************************************
     * Serialize heads
     * This will serialize http header and end CR(\r\n), then return serialized
     *size.
     ********************************************************************************/
    int32_t __serialize_header(std::string &buf) const;

  private:
    // Http head parse finished flag
    bool header_parsed_;
    // Http header map
    std::map<std::string, std::vector<std::string>> headers_;
};
DEFINE_SMART_POINTER_TYPE(header);

}  // namespace http
}  // namespace proto
}  // namespace pump

#endif
