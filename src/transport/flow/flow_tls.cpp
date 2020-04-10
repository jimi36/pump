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

#include "pump/transport/flow/flow_tls.h"

#ifdef USE_GNUTLS
extern "C" {
#include <gnutls/gnutls.h>
}
#endif

namespace pump {
	namespace transport {
		namespace flow {

			struct tls_session
			{
#ifdef USE_GNUTLS
				tls_session():
					session(nullptr)
				{}
				gnutls_session_t session;
#endif
			};

			class ssl_net_layer
			{
#ifdef USE_GNUTLS
			public:
				LIB_FORCEINLINE static ssize_t data_pull(gnutls_transport_ptr_t ptr, void_ptr data, size_t maxlen)
				{
					int32 size = flow_tls_ptr(ptr)->__read_from_net_read_cache((block_ptr)data, (int32)maxlen);
					if (size == 0)
						return -1;
					
					return size;
				}

				LIB_FORCEINLINE static ssize_t data_push(gnutls_transport_ptr_t ptr, c_void_ptr data, size_t len)
				{
					flow_tls_ptr(ptr)->__send_to_net_send_cache((c_block_ptr)data, (int32)len);
					return len;
				}

				LIB_FORCEINLINE static int get_error(gnutls_transport_ptr_t ptr)
				{
					return EAGAIN;
				}
#endif
			};

			flow_tls::flow_tls():
				is_handshaked_(false),
				session_(nullptr),
				read_task_(nullptr),
				net_read_data_size_(0),
				net_read_data_pos_(0),
				net_read_cache_raw_size_(0),
				net_read_cache_raw_(nullptr),
				ssl_read_cache_raw_size_(0),
				ssl_read_cache_raw_(nullptr),
				send_task_(nullptr)
			{
				read_flag_.clear();
			}

			flow_tls::~flow_tls()
			{
#ifdef USE_GNUTLS
				if (session_)
				{
					if (session_->session)
						gnutls_deinit(session_->session);
					delete session_;
				}

				if (read_task_)
					net::unlink_iocp_task(read_task_);
				if (send_task_)
					net::unlink_iocp_task(send_task_);
#endif
			}

			int32 flow_tls::init(
				poll::channel_sptr &ch, 
				int32 fd, 
				void_ptr tls_cert, 
				bool is_client
			) {
#ifdef USE_GNUTLS
				PUMP_ASSERT_EXPR(ch, ch_ = ch);
				PUMP_ASSERT_EXPR(fd > 0, fd_ = fd);

				PUMP_ASSERT(!session_);
				session_ = new tls_session();
				if (is_client)
					gnutls_init(&session_->session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
				else 
					gnutls_init(&session_->session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
				gnutls_set_default_priority(session_->session);
				// Set transport ptr
				gnutls_transport_set_ptr(session_->session, this);
				// Set GnuTLS session with credentials
				gnutls_credentials_set(session_->session, GNUTLS_CRD_CERTIFICATE, tls_cert);
				// Set GnuTLS handshake timeout time
				gnutls_handshake_set_timeout(session_->session, GNUTLS_INDEFINITE_TIMEOUT);
				//gnutls_handshake_set_timeout(session_->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
				// Set the callback that allows GnuTLS to PUSH data TO the transport layer
				gnutls_transport_set_push_function(session_->session, ssl_net_layer::data_push);
				// Set the callback that allows GnuTls to PULL data FROM the tranport layer
				gnutls_transport_set_pull_function(session_->session, ssl_net_layer::data_pull);
				// Set the callback that allows GnuTls to Get error if PULL or PUSH function error
				gnutls_transport_set_errno_function(session_->session, ssl_net_layer::get_error);
				
				ssl_read_cache_.resize(MAX_FLOW_BUFFER_SIZE);
				ssl_read_cache_raw_size_ = ssl_read_cache_.size();
				ssl_read_cache_raw_ = (block_ptr)ssl_read_cache_.data();

				net_read_cache_.resize(MAX_FLOW_BUFFER_SIZE*2);
				net_read_cache_raw_size_ = net_read_cache_.size();
				net_read_cache_raw_ = (block_ptr)net_read_cache_.data();

				read_task_ = net::new_iocp_task();
				net::set_iocp_task_fd(read_task_, fd_);
				net::set_iocp_task_notifier(read_task_, ch_);
				net::set_iocp_task_type(read_task_, IOCP_TASK_READ);
				net::set_iocp_task_buffer(read_task_, net_read_cache_raw_, net_read_cache_raw_size_);

				send_task_ = net::new_iocp_task();
				net::set_iocp_task_fd(send_task_, fd_);
				net::set_iocp_task_notifier(send_task_, ch_);
				net::set_iocp_task_type(send_task_, IOCP_TASK_SEND);

				return FLOW_ERR_NO;
#else
				return FLOW_ERR_ABORT;
#endif
			}

			void flow_tls::rebind_channel(poll::channel_sptr &ch)
			{
#ifdef USE_GNUTLS
				PUMP_ASSERT_EXPR(ch, ch_ = ch);

				if (read_task_)
					net::set_iocp_task_notifier(read_task_, ch_);
				if (send_task_)
					net::set_iocp_task_notifier(send_task_, ch_);
#endif
			}

			int32 flow_tls::handshake()
			{
#ifdef USE_GNUTLS
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

			int32 flow_tls::beg_read_task()
			{
#ifdef USE_GNUTLS
#	if defined(WIN32) && defined (USE_IOCP)
				if (read_flag_.test_and_set())
					return FLOW_ERR_BUSY;

				//PUMP_ASSERT(read_task_);
				if (!net::post_iocp_read(read_task_))
					return FLOW_ERR_ABORT;
#	endif
				return FLOW_ERR_NO;
#else
				return FLOW_ERR_ABORT;
#endif
			}

			void flow_tls::cancel_read_task()
			{
#ifdef USE_GNUTLS
#	if defined(WIN32) && defined (USE_IOCP)
				//net::cancel_iocp_task(net::get_iocp_handler(), read_task_);
#	endif
#endif
			}

			void flow_tls::end_read_task()
			{
#ifdef USE_GNUTLS
#	if defined(WIN32) && defined (USE_IOCP)
				read_flag_.clear();
#	endif
#endif
			}

			int32 flow_tls::read_from_net(net::iocp_task_ptr itask)
			{
#ifdef USE_GNUTLS
#	if defined(WIN32) && defined(USE_IOCP)
				int32 size = net::get_iocp_task_processed_size(itask);
#	else
				int32 size = net::read(fd_, net_read_cache_raw_, net_read_cache_raw_size_);
#	endif
				if (size > 0)
				{
					net_read_data_pos_ = 0;
					net_read_data_size_ = size;
					return FLOW_ERR_NO;
				}
				else if (size < 0)
				{
					return FLOW_ERR_AGAIN;
				}
#endif
				return FLOW_ERR_ABORT;
			}

			c_block_ptr flow_tls::read_from_ssl(int32_ptr size)
			{
#ifdef USE_GNUTLS
				*size = (int32)gnutls_read(session_->session, ssl_read_cache_raw_, ssl_read_cache_raw_size_);
#else
				*size = -1;
#endif
				return ssl_read_cache_raw_;
			}

			uint32 flow_tls::__read_from_net_read_cache(block_ptr b, int32 maxlen)
			{
#ifdef USE_GNUTLS
				// Get suitable size to read
				int32 size = net_read_data_size_ > maxlen ? maxlen : net_read_data_size_;
				if (size > 0)
				{
					// Copy read data to buffer.
					memcpy(b, net_read_cache_raw_ + net_read_data_pos_, size);
					net_read_data_pos_ += size;
					net_read_data_size_ -= size;
				}
				return size;
#else
				return 0;
#endif
			}

			int32 flow_tls::send_to_ssl(buffer_ptr wb)
			{
#ifdef USE_GNUTLS
				PUMP_ASSERT(wb);
				int32 size = (int32)gnutls_write(session_->session, wb->data(), wb->data_size());
				if (size > 0)
					wb->shift(size);
				return size;
#else
				return -1;
#endif
			}

			int32 flow_tls::want_to_send()
			{
#ifdef USE_GNUTLS
				//if (net_send_buffer_.data_size() == 0)
				//	PUMP_ASSERT(false);
				
#	if defined(WIN32) && defined(USE_IOCP)
				//PUMP_ASSERT(send_task_);
				net::set_iocp_task_buffer(send_task_, (int8_ptr)net_send_buffer_.data(), net_send_buffer_.data_size());
				if (net::post_iocp_send(send_task_))
					return FLOW_ERR_NO;
#	else
				int32 size = net::send(fd_, net_send_buffer_.data(), net_send_buffer_.data_size());
				if (size > 0)
				{
					if (!net_send_buffer_.shift(size))
						PUMP_ASSERT(false);
					return FLOW_ERR_NO;
				}
				else if (size < 0)
				{
					return FLOW_ERR_NO;
				}
#	endif
#endif
				return FLOW_ERR_ABORT;
			}

			int32 flow_tls::send_to_net(net::iocp_task_ptr itask)
			{
#ifdef USE_GNUTLS
				if (net_send_buffer_.data_size() == 0)
					return FLOW_ERR_NO_DATA;

#	if defined(WIN32) && defined(USE_IOCP)
				int32 size = net::get_iocp_task_processed_size(itask);
				if (size > 0)
				{
					if (!net_send_buffer_.shift(size))
						PUMP_ASSERT(false);

					if (net_send_buffer_.data_size() == 0)
					{
						net_send_buffer_.reset();
						return FLOW_ERR_NO;
					}
					
					net::set_iocp_task_buffer(send_task_, (block_ptr)net_send_buffer_.data(), net_send_buffer_.data_size());
					if (net::post_iocp_send(send_task_))
						return FLOW_ERR_AGAIN;
				}
#	else
				int32 size = net::send(fd_, net_send_buffer_.data(), net_send_buffer_.data_size());
				if (size > 0)
				{
					if (!net_send_buffer_.shift(size))
						PUMP_ASSERT(false);

					if (net_send_buffer_.data_size() > 0)
						return FLOW_ERR_AGAIN;

					net_send_buffer_.reset();
					return FLOW_ERR_NO;
				}
				else if (size < 0)
				{
					return FLOW_ERR_AGAIN;
				}
#	endif		
#endif
				return FLOW_ERR_ABORT;
			}

		}
	}
}