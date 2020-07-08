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

#ifndef pump_protocol_http_request_h
#define pump_protocol_http_request_h

#include "pump/protocol/http/header.h"
#include "pump/protocol/http/pocket.h"
#include "pump/protocol/http/content.h"
#include "pump/protocol/http/response.h"
#include "pump/protocol/http/connection.h"

namespace pump {
	namespace protocol {
		namespace http {

			enum request_method
			{
				METHOD_UNKNOWN = 0,
				METHOD_GET,
				METHOD_POST,
				METHOD_HEAD,
				METHOD_PUT,
				METHOD_DELETE
			};

			class request;
			DEFINE_ALL_POINTER_TYPE(request);

			class LIB_PUMP request :
				public pocket
			{
			public:
				/*********************************************************************************
				 * Constructor
				 * This construct a http request to serialize.
				 ********************************************************************************/
				request(void_ptr ctx = nullptr) noexcept;

				/*********************************************************************************
				 * Deconstructor
				 ********************************************************************************/
				virtual ~request() = default;

				/*********************************************************************************
				 * Set request method
				 ********************************************************************************/
				PUMP_INLINE void set_method(request_method method)
				{ method_ = method; }

				/*********************************************************************************
				 * Get request method
				 ********************************************************************************/
				PUMP_INLINE request_method get_method() const
				{ return method_; }

				/*********************************************************************************
				 * Set request url
				 ********************************************************************************/
				PUMP_INLINE void set_url(const std::string &url)
				{ uri_.parse_url(url); }

				/*********************************************************************************
				 * Get http uri
				 ********************************************************************************/
				PUMP_INLINE c_uri_ptr get_uri() const
				{ return (c_uri_ptr)&uri_; }
				PUMP_INLINE uri_ptr get_uri()
				{ return &uri_; }

				/*********************************************************************************
				 * Get context
				 ********************************************************************************/
				PUMP_INLINE void_ptr get_context() const
				{ return ctx_; }

				/*********************************************************************************
				 * Parse
				 * This parse http pocket, and return parsed size. If this return -1, it means
				 * parsed error.
				 ********************************************************************************/
				virtual int32 parse(c_block_ptr b, int32 size) override;

				/*********************************************************************************
				 * Serialize
				 * This will serialize http pocket and return serialized size.
				 ********************************************************************************/
				virtual int32 serialize(std::string &buf) const override;

			private:
				/*********************************************************************************
				 * Parse http start line
				 ********************************************************************************/
				int32 __parse_start_line(c_block_ptr b, int32 size);

				/*********************************************************************************
				 * Serialize http request line
				 ********************************************************************************/
				int32 __serialize_request_line(std::string &buffer) const;

			private:
				// Request context
				void_ptr ctx_;

				// Request uri
				uri uri_;

				// Request method
				request_method method_;
			};

		}
	}
}

#endif