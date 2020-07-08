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

#include "pump/utils.h"
#include "pump/protocol/http/utils.h"
#include "pump/protocol/http/request.h"

namespace pump {
	namespace protocol {
		namespace http {

			static c_block_ptr request_method_strings[] =
			{
				"UNKNOWN",
				"GET",
				"POST",
				"HEAD",
				"PUT",
				"DELETE"
			};

			request::request(void_ptr ctx) noexcept :
				pocket(PK_REQUEST),
				ctx_(ctx),
				method_(METHOD_UNKNOWN)
			{
			}

			int32 request::parse(c_block_ptr b, int32 size)
			{
				if (parse_status_ == PARSE_FINISHED)
					return 0;

				if (parse_status_ == PARSE_NONE)
					parse_status_ = PARSE_LINE;

				c_block_ptr pos = b;
				int32 parse_size = 0;
				if (parse_status_ == PARSE_LINE)
				{
					parse_size = __parse_start_line(pos, size);
					if (parse_size <= 0)
						return parse_size;

					pos += parse_size;
					size -= parse_size;

					parse_status_ = PARSE_HEADER;
				}

				if (parse_status_ == PARSE_HEADER)
				{
					parse_size = header_.parse(pos, size);
					if (parse_size < 0)
						return parse_size;
					else if (parse_size == 0)
						return int32(pos - b);

					pos += parse_size;
					size -= parse_size;

					if (header_.is_parse_finished())
					{
						parse_status_ = PARSE_CONTENT;

						std::string host;
						if (header_.get("Host", host))
							uri_.set_host(host);
					}
				}

				if (parse_status_ == PARSE_CONTENT)
				{
					content_ptr ct = ct_.get();
					if (ct == nullptr)
					{
						int32 ct_length = 0;
						if (header_.get("Content-Length", ct_length) && ct_length > 0)
						{
							ct = new content();
							ct->set_length_to_parse(ct_length);
							ct_.reset(ct);
						}
						else
						{
							std::string transfer_encoding;
							if (header_.get("Transfer-Encoding", transfer_encoding) && transfer_encoding == "chunked")
							{
								ct = new content();
								ct->set_chunked();
								ct_.reset(ct);
							}
							else
							{
								parse_status_ = PARSE_FINISHED;
							}
						}
					}

					if (ct)
					{
						parse_size = ct->parse(pos, size);
						if (parse_size < 0)
							return parse_size;
						else if (parse_size == 0)
							return pump::int32(pos - b);

						pos += parse_size;
						size -= parse_size;

						if (ct->is_parse_finished())
							parse_status_ = PARSE_FINISHED;
					}
				}

				return int32(pos - b);
			}

			int32 request::serialize(std::string &buffer) const
			{
				int32 size = -1;
				int32 serialize_size = 0;

				size = __serialize_request_line(buffer);
				if (size < 0)
					return -1;
				serialize_size += size;

				size = header_.serialize(buffer);
				if (size < 0)
					return -1;
				serialize_size += size;

				if (ct_)
				{
					size = ct_->serialize(buffer);
					if (size < 0)
						return -1;
					serialize_size += size;
				}

				return serialize_size;
			}

			int32 request::__parse_start_line(c_block_ptr b, int32 size)
			{
				c_block_ptr pos = b;

				// parse line end
				c_block_ptr line_end = find_http_line_end(pos, size);
				if (line_end == nullptr)
					return 0;

				// parse request method
				if (pos + 4 < line_end && memcmp(pos, "GET ", 4) == 0)
					method_ = METHOD_GET, pos += 4;
				else if (pos + 5 < line_end && memcmp(pos, "POST ", 5) == 0)
					method_ = METHOD_POST, pos += 5;
				else if (pos + 5 < line_end && memcmp(pos, "HEAD ", 5) == 0)
					method_ = METHOD_HEAD, pos += 5;
				else if (pos + 4 < line_end && memcmp(pos, "PUT ", 4) == 0)
					method_ = METHOD_PUT, pos += 4;
				else if (pos + 7 < line_end && memcmp(pos, "DELETE ", 7) == 0)
					method_ = METHOD_DELETE, pos += 7;
				else
					return -1;

				// parse http path
				c_block_ptr tmp = pos;
				while (pos < line_end && *pos != ' ' && *pos != '?')
					++pos;
				if (pos == tmp || pos == line_end)
					return -1;
				uri_.set_path(std::string(tmp, pos));

				// parse http params
				if (*pos == '?')
				{
					tmp = ++pos;
					while (pos < line_end && *pos != ' ')
						++pos;
					if (pos == tmp || pos == line_end)
						return -1;

					std::string params;
					std::string tmp_params(tmp, pos);
					if (!url_decode(tmp_params, params))
						return -1;

					auto vals = split_string(params, "[=&]");
					uint32 cnt = (uint32)vals.size();
					if (vals.empty() || cnt % 2 != 0)
						return -1;
					for (uint32 i = 0; i < cnt; i += 2)
					{
						uri_.set_param(vals[i], vals[i + 1]);
					}
				}
				++pos;

				// parse http version
				if (memcmp(pos, "HTTP/1.0", 8) == 0)
					version_ = VERSION_10;
				else if (memcmp(pos, "HTTP/1.1", 8) == 0)
					version_ = VERSION_11;
				else if (memcmp(pos, "HTTP/2.0", 8) == 0)
					version_ = VERSION_20;
				else
					return -1;

				return int32(line_end - b);
			}

			int32 request::__serialize_request_line(std::string &buf) const
			{
				block tmp[256] = { 0 };
				int32 size = snprintf(tmp, sizeof(tmp), "%s %s %s\r\n",
					request_method_strings[method_], uri_.get_path().c_str(), get_http_version_string().c_str());
				buf.append(tmp);
				return size;
			}

		}
	}
}