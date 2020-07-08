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

#include "net/iocp.h"
#include "net/socket.h"
#include "pump/transport/flow/flow_tls.h"

#if defined(USE_GNUTLS)
extern "C" {
	#include <gnutls/gnutls.h>
}
#endif

namespace pump {
	namespace transport {
		namespace flow {

			struct tls_session
			{
#if defined(USE_GNUTLS)
				tls_session() noexcept :
					session(nullptr)
				{}

				~tls_session()
				{
					if (session)
						gnutls_deinit(session);
				}

				gnutls_session_t session;
#endif
			};

			class ssl_net_layer
			{
#if defined(USE_GNUTLS)
			public:
				PUMP_INLINE static ssize_t data_pull(gnutls_transport_ptr_t ptr, void_ptr data, size_t maxlen)
				{
					int32 size = flow_tls_ptr(ptr)->__read_from_net_read_cache((block_ptr)data, (int32)maxlen);
					if (size == 0)
						return -1;
					
					return size;
				}

				PUMP_INLINE static ssize_t data_push(gnutls_transport_ptr_t ptr, c_void_ptr data, size_t len)
				{
					flow_tls_ptr(ptr)->__send_to_net_send_cache((c_block_ptr)data, (int32)len);
					return len;
				}

				PUMP_INLINE static int get_error(gnutls_transport_ptr_t ptr)
				{
					return EAGAIN;
				}
#endif
			};

			flow_tls::flow_tls() noexcept :
				is_handshaked_(false),
				session_(nullptr),
				read_task_(nullptr),
				net_read_data_pos_(0),
				net_read_data_size_(0),
				send_task_(nullptr)
			{
			}

			flow_tls::~flow_tls()
			{
				close();

#if defined(USE_GNUTLS)
				if (session_)
					delete session_;

				if (read_task_)
					net::unlink_iocp_task(read_task_);
				if (send_task_)
					net::unlink_iocp_task(send_task_);
#endif
			}

			int32 flow_tls::init(poll::channel_sptr &ch, int32 fd, void_ptr xcred, bool client)
			{
#if defined(USE_GNUTLS)
				PUMP_DEBUG_ASSIGN(ch, ch_, ch);
				PUMP_DEBUG_ASSIGN(fd > 0, fd_, fd);

				PUMP_ASSERT(!session_);
				session_ = object_create<tls_session>();
				if (client)
					gnutls_init(&session_->session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
				else 
					gnutls_init(&session_->session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
				gnutls_set_default_priority(session_->session);
				// Set transport ptr
				gnutls_transport_set_ptr(session_->session, this);
				// Set GnuTLS session with credentials
				gnutls_credentials_set(session_->session, GNUTLS_CRD_CERTIFICATE, xcred);
				// Set GnuTLS handshake timeout time
				gnutls_handshake_set_timeout(session_->session, GNUTLS_INDEFINITE_TIMEOUT);
				//gnutls_handshake_set_timeout(session_->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
				// Set the callback that allows GnuTLS to PUSH data TO the transport layer
				gnutls_transport_set_push_function(session_->session, ssl_net_layer::data_push);
				// Set the callback that allows GnuTls to PULL data FROM the tranport layer
				gnutls_transport_set_pull_function(session_->session, ssl_net_layer::data_pull);
				// Set the callback that allows GnuTls to Get error if PULL or PUSH function error
				gnutls_transport_set_errno_function(session_->session, ssl_net_layer::get_error);

				auto read_task = net::new_iocp_task();
				net::set_iocp_task_fd(read_task, fd_);
				net::set_iocp_task_notifier(read_task, ch_);
				net::set_iocp_task_type(read_task, IOCP_TASK_READ);
				net::set_iocp_task_buffer(read_task, net_read_cache_, sizeof(net_read_cache_));

				auto send_task = net::new_iocp_task();
				net::set_iocp_task_fd(send_task, fd_);
				net::set_iocp_task_notifier(send_task, ch_);
				net::set_iocp_task_type(send_task, IOCP_TASK_SEND);

				read_task_ = read_task;
				send_task_ = send_task;

				return FLOW_ERR_NO;
#else
				return FLOW_ERR_ABORT;
#endif
			}

			void flow_tls::rebind_channel(poll::channel_sptr &ch)
			{
#if defined(USE_GNUTLS)
				PUMP_DEBUG_ASSIGN(ch, ch_, ch);

				net::set_iocp_task_notifier(read_task_, ch_);
				net::set_iocp_task_notifier(send_task_, ch_);
#endif
			}

			int32 flow_tls::handshake()
			{
#if defined(USE_GNUTLS)
				if (is_handshaked_)
					return FLOW_ERR_NO;

				// Now we perform the actual SSL/TLS handshake.
				// If you wanted to, you could send some data over the tcp socket before
				// giving it to GnuTLS and performing the handshake. See the GnuTLS manual
				// on STARTTLS for more information.
				int32 ret = gnutls_handshake(session_->session);

				// GnuTLS manual says to keep trying until it returns zero (success) or
				// encounters a fatal error.
				if (ret != 0 && gnutls_error_is_fatal(ret) != 0)
					return FLOW_ERR_ABORT;

				// Flow handshakes success if ret is requal zero. 
				if (ret == 0)
					is_handshaked_ = true;

				return FLOW_ERR_NO;
#else
				return FLOW_ERR_ABORT;
#endif
			}

			int32 flow_tls::want_to_read()
			{
#if defined(USE_GNUTLS)
	#if defined(WIN32) && defined (USE_IOCP)
				if (!net::post_iocp_read(read_task_))
					return FLOW_ERR_ABORT;
	#endif
				return FLOW_ERR_NO;
#else
				return FLOW_ERR_ABORT;
#endif
			}

			int32 flow_tls::read_from_net(void_ptr iocp_task)
			{
#if defined(USE_GNUTLS)
	#if defined(WIN32) && defined(USE_IOCP)
				int32 size = net::get_iocp_task_processed_size(iocp_task);
	#else
				int32 size = net::read(fd_, net_read_cache_, sizeof(net_read_cache_));
	#endif
				if (PUMP_LIKELY(size > 0))
				{
					net_read_data_pos_ = 0;
					net_read_data_size_ = size;
					return FLOW_ERR_NO;
				}
#endif
				return FLOW_ERR_ABORT;
			}

			c_block_ptr flow_tls::read_from_ssl(int32_ptr size)
			{
#if defined(USE_GNUTLS)
				*size = (int32)gnutls_read(session_->session, ssl_read_cache_, sizeof(ssl_read_cache_));
				if (*size <= 0 && gnutls_error_is_fatal(*size) != 0)
					return nullptr;
				return ssl_read_cache_;
#else
				*size = -1;
				return nullptr;
#endif
			}

			uint32 flow_tls::__read_from_net_read_cache(block_ptr b, int32 maxlen)
			{
#if defined(USE_GNUTLS)
				// Get suitable size to read
				int32 size = net_read_data_size_ > maxlen ? maxlen : net_read_data_size_;
				if (size > 0)
				{
					// Copy read data to buffer.
					memcpy(b, net_read_cache_ + net_read_data_pos_, size);
					net_read_data_pos_ += size;
					net_read_data_size_ -= size;
				}
				return size;
#else
				return 0;
#endif
			}

			bool flow_tls::send_to_ssl(buffer_ptr wb)
			{
#if defined(USE_GNUTLS)
				PUMP_ASSERT(wb && wb->data_size() > 0);
				do
				{
					int32 size = (int32)gnutls_write(session_->session, wb->data(), wb->data_size());
					if (size <= 0 || !wb->shift(size))
						break;
					if (wb->data_size() == 0)
						return true;
				} while (true);
#endif
				return false;
			}

			int32 flow_tls::want_to_send()
			{
#if defined(USE_GNUTLS)
	#if defined(WIN32) && defined(USE_IOCP)
				net::set_iocp_task_buffer(
					send_task_, 
					(block_ptr)net_send_buffer_.data(), 
					net_send_buffer_.data_size()
				);
				if (net::post_iocp_send(send_task_))
					return FLOW_ERR_NO;
	#else
				int32 size = net::send(fd_, net_send_buffer_.data(), net_send_buffer_.data_size());
				if (PUMP_LIKELY(size > 0))
				{
					PUMP_DEBUG_CHECK(net_send_buffer_.shift(size));
					return FLOW_ERR_NO;
				}
				else if (size < 0)
				{
					return FLOW_ERR_NO;
				}
	#endif
#endif
				return FLOW_ERR_ABORT;
			}

			int32 flow_tls::send_to_net(void_ptr iocp_task)
			{
#if defined(USE_GNUTLS)
				auto data_size = net_send_buffer_.data_size();
				if (data_size == 0)
					return FLOW_ERR_NO;

	#if defined(WIN32) && defined(USE_IOCP)
				int32 size = net::get_iocp_task_processed_size(iocp_task);
				if (PUMP_LIKELY(size > 0))
				{
					PUMP_DEBUG_CHECK(net_send_buffer_.shift(size));

					data_size -= size;
					if (data_size > 0)
					{
						net::set_iocp_task_buffer(
							send_task_, 
							(block_ptr)net_send_buffer_.data(), 
							data_size
						);
						if (net::post_iocp_send(send_task_))
							return FLOW_ERR_AGAIN;
					}
					
					net_send_buffer_.reset();
					return FLOW_ERR_NO;
				}
	#else
				int32 size = net::send(fd_, net_send_buffer_.data(), data_size);
				if (PUMP_LIKELY(size > 0))
				{
					PUMP_DEBUG_CHECK(net_send_buffer_.shift(size));
					if (data_size - size > 0)
						return FLOW_ERR_AGAIN;

					net_send_buffer_.reset();
					return FLOW_ERR_NO;
				}
				else if (size < 0)
				{
					return FLOW_ERR_AGAIN;
				}
	#endif		
#endif
				return FLOW_ERR_ABORT;
			}

		}
	}
}
