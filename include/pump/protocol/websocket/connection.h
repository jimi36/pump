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

#ifndef pump_protocol_websocket_connection_h
#define pump_protocol_websocket_connection_h

#include "pump/protocol/http/request.h"
#include "pump/protocol/http/response.h"
#include "pump/protocol/websocket/frame.h"

namespace pump {
	namespace protocol {
		namespace websocket {

			class connection;
			DEFINE_ALL_POINTER_TYPE(connection);

			struct connection_callbacks
			{
				pump_function<
					void(c_block_ptr, uint32, bool)
				> data_cb;

				pump_function<
					void(const std::string&)
				> error_cb;
			};

			class LIB_PUMP connection :
				public std::enable_shared_from_this<connection>
			{
			public:
				/*********************************************************************************
				 * Constructor
				 ********************************************************************************/
				connection(bool has_mask) noexcept;

				/*********************************************************************************
				 * Deconstructor
				 ********************************************************************************/
				virtual ~connection() = default;


				/*********************************************************************************
				 * Upgrade http connection
				 ********************************************************************************/
				bool upgrade(http::connection_sptr &conn);

				/*********************************************************************************
				 * Start
				 ********************************************************************************/
				bool start(const connection_callbacks &cbs);

				/*********************************************************************************
				 * Stop
				 ********************************************************************************/
				void stop();

				/*********************************************************************************
				 * Send
				 ********************************************************************************/
				bool send(c_block_ptr b, uint32 size);

				/*********************************************************************************
				 * Check connection is valid or not
				 ********************************************************************************/
				PUMP_INLINE bool is_valid() const
				{ return transp_ && transp_->is_started(); }

			protected:
				/*********************************************************************************
				 * Read event callback
				 ********************************************************************************/
				static void on_read(connection_wptr wptr, c_block_ptr b, int32 size);

				/*********************************************************************************
				 * Disconnected event callback
				 ********************************************************************************/
				static void on_disconnected(connection_wptr wptr);

				/*********************************************************************************
				 * Stopped event callback
				 ********************************************************************************/
				static void on_stopped(connection_wptr wptr);

			protected:
				/*********************************************************************************
				 * Handle connection closed
				 ********************************************************************************/
				static void on_error(connection_wptr wptr, const std::string &msg);

			private:
				/*********************************************************************************
				 * Handle frame
				 ********************************************************************************/
				int32 __handle_frame(c_block_ptr b, uint32 size);

				/*********************************************************************************
				 * Send ping frame
				 ********************************************************************************/
				void __send_ping_frame();

				/*********************************************************************************
				 * Send pong
				 ********************************************************************************/
				void __send_pong_frame();

				/*********************************************************************************
				 * Send close frame
				 ********************************************************************************/
				void __send_close_frame();

			private:
				/*********************************************************************************
				 * Constructor
				 ********************************************************************************/
				connection(bool server, transport::base_transport_sptr &transp) noexcept;

			private:
				// Service 
				service_ptr sv_;

				// Frame mask
				bool has_mask_;
				uint8 mask_key_[4];

				// Transport
				transport::base_transport_sptr transp_;

				// Websocket closed status
				std::atomic_flag closed_;

				// Read Cache
				std::string read_cache_;

				// Frame decode info
				int16 decode_phase_;
				frame_header decode_hdr_;

				// Websocket callbacks
				connection_callbacks cbs_;
			};
			DEFINE_ALL_POINTER_TYPE(connection);

		}
	}
}

#endif