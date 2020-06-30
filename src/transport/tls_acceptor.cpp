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

#include "pump/transport/tls_acceptor.h"
#include "pump/transport/tls_transport.h"

#if defined(USE_GNUTLS)
extern "C" {
	#include <gnutls/gnutls.h>
}
#endif

namespace pump {
	namespace transport {

		tls_acceptor::tls_acceptor(
			bool use_file,
			PUMP_CONST std::string &cert,
			PUMP_CONST std::string &key,
			PUMP_CONST address &listen_address,
			int64 handshake_timeout
		) : 
			base_acceptor(TYPE_TLS_ACCEPTOR, listen_address),
			xcred_(nullptr),
			handshake_timeout_(0)
		{
#if defined(USE_GNUTLS)
			gnutls_certificate_credentials_t xcred;
			int32 ret1 = gnutls_certificate_allocate_credentials(&xcred);
			if (ret1 != 0)
				return;
			
			if (use_file)
			{
				int32 ret = gnutls_certificate_set_x509_key_file(xcred, cert.c_str(), key.c_str(), GNUTLS_X509_FMT_PEM);
				if (ret != 0)
					return;
			}
			else
			{
				gnutls_datum_t gnutls_cert;
				gnutls_cert.data = (unsigned char *)cert.data();
				gnutls_cert.size = cert.size();

				gnutls_datum_t gnutls_key;
				gnutls_key.data = (unsigned char *)key.data();
				gnutls_key.size = key.size();

				int32 ret2 = gnutls_certificate_set_x509_key_mem(xcred, &gnutls_cert, &gnutls_key, GNUTLS_X509_FMT_PEM);
				if (ret2 != 0)
					return;
			}

			xcred_ = xcred;
#endif
		}

		tls_acceptor::~tls_acceptor()
		{
#if defined(USE_GNUTLS)
			if (xcred_ != nullptr)
				gnutls_certificate_free_credentials((gnutls_certificate_credentials_t)xcred_);
#endif
		}

		transport_error tls_acceptor::start(
			service_ptr sv, 
			PUMP_CONST acceptor_callbacks &cbs
		) {
			if (!__set_status(STATUS_INIT, STATUS_STARTED))
				return ERROR_INVALID;

			PUMP_ASSERT(xcred_ != nullptr);
			PUMP_ASSERT_EXPR(sv != nullptr, __set_service(sv));
			PUMP_ASSERT_EXPR(cbs.accepted_cb && cbs.stopped_cb, cbs_ = cbs);

			handshaker_cbs_.handshaked_cb = function::bind(&tls_acceptor::on_handshaked,
				shared_from_this(), _1, _2);
			handshaker_cbs_.stopped_cb = function::bind(&tls_acceptor::on_handshake_stopped,
				shared_from_this(), _1);

			utils::scoped_defer defer([&]() {
				__close_flow();
				__stop_tracker();
				__set_status(STATUS_STARTED, STATUS_ERROR);
			});

			if (!__open_flow())
				return ERROR_FAULT;

			poll::channel_sptr ch = std::move(shared_from_this());
			if (!__start_tracker(ch))
				return ERROR_FAULT;

			if (flow_->want_to_accept() != FLOW_ERR_NO)
				return ERROR_FAULT;

			defer.clear();

			return ERROR_OK;
		}

		void tls_acceptor::stop()
		{
			// When stopping done, tracker event will trigger stopped callback.
			if (__set_status(STATUS_STARTED, STATUS_STOPPING))
			{
				__close_flow();
				__stop_tracker();
				__stop_all_handshakers();
			}
		}

		void tls_acceptor::on_read_event(net::iocp_task_ptr itask)
		{
			auto flow = flow_.get();

			address local_address, remote_address;
			int32 fd = flow->accept(itask, &local_address, &remote_address);
			if (PUMP_LIKELY(fd > 0))
			{
				tls_handshaker_ptr handshaker = __create_handshaker();
				if (PUMP_LIKELY(handshaker != nullptr))
				{
					// If handshaker is started error, handshaked callback will be triggered. So we do nothing
					// at here when started error. But if acceptor stopped befere here, we shuold stop handshaking.
					handshaker->init(fd, false, xcred_, local_address, remote_address);
					if (handshaker->start(get_service(), handshake_timeout_, handshaker_cbs_))
					{
						if (__is_status(STATUS_STOPPING) || __is_status(STATUS_STOPPED))
							handshaker->stop();
					}
				}
				else
				{
					net::close(fd);
				}
			}

			// Acceptor maybe be stopped, so we need check it in started status.
			if (__is_status(STATUS_STARTED) && flow->want_to_accept() != FLOW_ERR_NO)
				PUMP_ASSERT(false);
		}

		void tls_acceptor::on_handshaked(
			tls_acceptor_wptr wptr,
			tls_handshaker_ptr handshaker,
			bool succ
		) {
			PUMP_LOCK_WPOINTER(acceptor, wptr);
			if (acceptor == nullptr)
			{
				handshaker->stop();
				return;
			}

			acceptor->__remove_handshaker(handshaker);

			if (succ && acceptor->__is_status(STATUS_STARTED))
			{
				auto flow = handshaker->unlock_flow();
				address local_address = handshaker->get_local_address();
				address remote_address = handshaker->get_remote_address();
				auto transport = tls_transport::create_instance();
				transport->init(flow, local_address, remote_address);

				acceptor->cbs_.accepted_cb(transport);
			}			
		}

		void tls_acceptor::on_handshake_stopped(
			tls_acceptor_wptr wptr, 
			tls_handshaker_ptr handshaker
		) {
			PUMP_LOCK_WPOINTER(acceptor, wptr);
			if (acceptor == nullptr)
				return;

			acceptor->__remove_handshaker(handshaker);
		}

		bool tls_acceptor::__open_flow()
		{
			// Setup flow
			PUMP_ASSERT(!flow_);
			flow_.reset(new flow::flow_tls_acceptor());
			poll::channel_sptr ch = shared_from_this();
			if (flow_->init(ch, listen_address_) != FLOW_ERR_NO)
				return false;

			// Set channel fd
			channel::__set_fd(flow_->get_fd());

			return true;
		}

		tls_handshaker_ptr tls_acceptor::__create_handshaker()
		{
			tls_handshaker_sptr handshaker(new tls_handshaker);
			{
				std::lock_guard<std::mutex> lock(handshaker_mx_);
				handshakers_[handshaker.get()] = handshaker;
			}
			return handshaker.get();
		}

		void tls_acceptor::__remove_handshaker(tls_handshaker_ptr handshaker)
		{
			std::lock_guard<std::mutex> lock(handshaker_mx_);
			handshakers_.erase(handshaker);
		}

		void tls_acceptor::__stop_all_handshakers()
		{
			std::lock_guard<std::mutex> lock(handshaker_mx_);
			for (auto hs : handshakers_)
				hs.second->stop();
		}

	}
}
