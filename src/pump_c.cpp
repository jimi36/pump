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

#include "pump/init.h"
#include "pump/service.h"
#include "pump/time/timer.h"
#include "pump/transport/tcp_dialer.h"
#include "pump/transport/tls_dialer.h"
#include "pump/transport/tcp_acceptor.h"
#include "pump/transport/tls_acceptor.h"

#include "pump/pump_c.h"

using namespace pump;

void pump_c_init() {
    init();
}

void pump_c_uninit() {
    uninit();
}

struct pump_c_service_impl {
    service_ptr sv;
};

pump_c_service pump_c_service_create(int with_poller) {
    pump_c_service_impl *impl = object_create<pump_c_service_impl>();
    impl->sv = object_create<service>(with_poller);
    if (!impl->sv) {
        object_delete(impl);
        return nullptr;
    }
    return impl;
}

void pump_c_service_destory(pump_c_service sv) {
    pump_c_service_impl *impl = (pump_c_service_impl*)sv;
    PUMP_ASSERT(impl);

    if (impl->sv) {
        object_delete(impl->sv);
        impl->sv = nullptr;
    }

    object_delete(impl);
}

int pump_c_service_start(pump_c_service sv) {
    pump_c_service_impl *impl = (pump_c_service_impl*)sv;
    PUMP_ASSERT(impl && impl->sv);

    if (!impl->sv->start()) {
        return -1;
    }

    return 0;
}

int pump_c_service_stop(pump_c_service sv) {
    pump_c_service_impl *impl = (pump_c_service_impl*)sv;
    PUMP_ASSERT(impl && impl->sv);

    impl->sv->stop();
    impl->sv->wait_stopped();

    return 0;
}

struct pump_c_timer_impl {
    time::timer_sptr t;
};

pump_c_timer pump_c_timer_create(
    int timeout_ms, 
    int repeated, 
    pump_c_timeout_callback cb_func) {
    pump_c_timer_impl *impl = object_create<pump_c_timer_impl>();

    time::timer_callback cb = pump_bind(cb_func);
    impl->t = time::timer::create(timeout_ms, cb, repeated);

    return impl;
}

void pump_c_timer_destory(pump_c_timer timer) {
    PUMP_ASSERT(timer);
    object_delete((pump_c_timer_impl*)timer);
}

int pump_c_timer_start(
    pump_c_service sv, 
    pump_c_timer timer) {
    pump_c_service_impl *impl_sv = (pump_c_service_impl*)sv;
    PUMP_ASSERT(impl_sv && impl_sv->sv);

    pump_c_timer_impl *impl_timer = (pump_c_timer_impl*)timer;
    PUMP_ASSERT(impl_timer);
    if (!impl_sv->sv->start_timer(impl_timer->t)) {
        return -1;
    }

    return 0;
}

int pump_c_timer_stop(pump_c_timer timer) {
    pump_c_timer_impl *impl = (pump_c_timer_impl*)timer;
    PUMP_ASSERT(impl);

    impl->t->stop();

    return 0;
}

struct pump_c_acceptor_impl {
    pump_c_acceptor_callbacks cbs;
    transport::base_acceptor_sptr acceptor;
};

struct pump_c_dialer_impl {
    pump_c_dialer_callbacks cbs;
    transport::base_dialer_sptr dialer;
};

struct pump_c_transport_impl {
    pump_c_transport_callbacks cbs;
    transport::base_transport_sptr transp;
};

pump_c_acceptor pump_c_tcp_acceptor_create(
    const char *ip, 
    int port) {
    pump_c_acceptor_impl *impl = object_create<pump_c_acceptor_impl>();

    transport::address addr(ip, port);
    impl->acceptor = transport::tcp_acceptor::create(addr);

    impl->cbs.accepted_cb = nullptr;
    impl->cbs.stopped_cb = nullptr;

    return impl;
}

pump_c_acceptor pump_c_tls_acceptor_create(
    const char *ip, 
    int port,
    const char *cert,
    const char *key) {
    pump_c_acceptor_impl *impl = object_create<pump_c_acceptor_impl>();

    transport::address addr(ip, port);
    impl->acceptor =
        transport::tls_acceptor::create_with_memory(cert, key, addr, 1000);

    impl->cbs.accepted_cb = nullptr;
    impl->cbs.stopped_cb = nullptr;

    return impl;
}

void pump_c_acceptor_destory(pump_c_acceptor acceptor) {
    PUMP_ASSERT(acceptor);
    object_delete((pump_c_acceptor_impl*)acceptor);
}

static void on_acceptor_accepted_cb(
    pump_c_acceptor_impl *impl,
    transport::base_transport_sptr &transp) {
    if (impl->cbs.accepted_cb) {
        pump_c_transport_impl *impl_transp = object_create<pump_c_transport_impl>();
        impl_transp->transp = transp;
        impl_transp->cbs.read_cb = nullptr;
        impl_transp->cbs.read_from_cb = nullptr;
        impl_transp->cbs.disconnected_cb = nullptr;
        impl_transp->cbs.stopped_cb = nullptr;

        impl->cbs.accepted_cb(impl, impl_transp);
    }
}

static void on_acceptor_stopped_cb(pump_c_acceptor_impl *impl) {
    if (impl->cbs.stopped_cb) {
        impl->cbs.stopped_cb(impl);
    }
}

int pump_c_acceptor_start(
    pump_c_service sv,
    pump_c_acceptor acceptor, 
    struct pump_c_acceptor_callbacks cbs) {
    pump_c_service_impl *impl_sv = (pump_c_service_impl*)sv;
    PUMP_ASSERT(impl_sv && impl_sv->sv);

    pump_c_acceptor_impl *impl_acceptor = (pump_c_acceptor_impl*)acceptor;
    PUMP_ASSERT(impl_acceptor && impl_acceptor->acceptor);

    impl_acceptor->cbs = cbs;
    
    transport::acceptor_callbacks impl_cbs;
    impl_cbs.accepted_cb = pump_bind(on_acceptor_accepted_cb, impl_acceptor, _1);
    impl_cbs.stopped_cb = pump_bind(on_acceptor_stopped_cb, impl_acceptor);
    if (impl_acceptor->acceptor->start(impl_sv->sv, impl_cbs) != 0) {
        return -1;
    }

    return 0;
}

int pump_c_acceptor_stop(pump_c_acceptor acceptor) {
    pump_c_acceptor_impl *impl_acceptor = (pump_c_acceptor_impl*)acceptor;
    PUMP_ASSERT(impl_acceptor && impl_acceptor->acceptor);

    impl_acceptor->acceptor->stop();

    return 0;
}

pump_c_acceptor pump_c_tcp_dialer_create(
    const char *local_ip, 
    int local_port,
    const char *remote_ip, 
    int remote_port) {
    pump_c_dialer_impl *impl = object_create<pump_c_dialer_impl>();

    transport::address local_addr(local_ip, local_port);
    transport::address remote_addr(remote_ip, remote_port);
    impl->dialer = transport::tcp_dialer::create(local_addr, remote_addr, 1000);

    impl->cbs.dialed_cb = nullptr;
    impl->cbs.stopped_cb = nullptr;
    impl->cbs.timeouted_cb = nullptr;

    return impl;
}

pump_c_acceptor pump_c_tls_dialer_create(
    const char *local_ip, 
    int local_port,
    const char *remote_ip, 
    int remote_port) {
    pump_c_dialer_impl *impl = object_create<pump_c_dialer_impl>();

    transport::address local_addr(local_ip, local_port);
    transport::address remote_addr(remote_ip, remote_port);
    impl->dialer = transport::tls_dialer::create(local_addr, remote_addr, 1000, 1000);

    impl->cbs.dialed_cb = nullptr;
    impl->cbs.stopped_cb = nullptr;
    impl->cbs.timeouted_cb = nullptr;

    return impl;
}

void pump_c_dialer_destory(pump_c_dialer dialer) {
    PUMP_ASSERT(dialer);
    object_delete((pump_c_dialer_impl*)dialer);
}

static void on_dialer_dialed(
    pump_c_dialer_impl *impl, 
    transport::base_transport_sptr &transp, 
    bool succ) {
    if (impl->cbs.dialed_cb) {
        pump_c_transport_impl *impl_transp = nullptr;
        if (succ) {
            impl_transp = object_create<pump_c_transport_impl>();
            impl_transp->transp = transp;
            impl_transp->cbs.read_cb = nullptr;
            impl_transp->cbs.read_from_cb = nullptr;
            impl_transp->cbs.disconnected_cb = nullptr;
            impl_transp->cbs.stopped_cb = nullptr;
        }
        impl->cbs.dialed_cb(impl, impl_transp, succ ? 1 : 0);
    }
}

static void on_dialer_timeouted(pump_c_dialer_impl *impl) {
    if (impl->cbs.timeouted_cb) {
        impl->cbs.timeouted_cb(impl);
    }
}

static void on_dialer_stopped(pump_c_dialer_impl *impl) {
    if (impl->cbs.stopped_cb) {
        impl->cbs.stopped_cb(impl);
    }
}

int pump_c_dialer_start(
    pump_c_service sv,
    pump_c_dialer dialer,
    struct pump_c_dialer_callbacks cbs) {
    pump_c_service_impl *impl_sv = (pump_c_service_impl*)sv;
    PUMP_ASSERT(impl_sv && impl_sv->sv);

    pump_c_dialer_impl *impl_dialer = (pump_c_dialer_impl*)dialer;
    PUMP_ASSERT(impl_dialer && impl_dialer->dialer);
    
    impl_dialer->cbs = cbs;

    transport::dialer_callbacks impl_cbs;
    impl_cbs.dialed_cb = pump_bind(on_dialer_dialed, impl_dialer, _1, _2);
    impl_cbs.timeouted_cb = pump_bind(on_dialer_timeouted, impl_dialer);
    impl_cbs.stopped_cb = pump_bind(on_dialer_stopped, impl_dialer);
    if (impl_dialer->dialer->start(impl_sv->sv, impl_cbs) != 0) {
        return -1;
    }

    return 0;
}

int pump_c_dialer_stop(pump_c_dialer dialer) {
    pump_c_dialer_impl *impl_dialer = (pump_c_dialer_impl*)dialer;
    PUMP_ASSERT(impl_dialer && impl_dialer->dialer);

    impl_dialer->dialer->stop();

    return 0;
}

void pump_c_transport_destory(pump_c_transport transp) {
    PUMP_ASSERT(transp);
    object_delete((pump_c_transport_impl*)transp);
}

static void on_transport_read(
    pump_c_transport_impl *impl, 
    const char *b, 
    int size) {
    if (impl->cbs.read_cb) {
        impl->cbs.read_cb(impl, b, size);
    }
}

static void on_transport_read_from(
    pump_c_transport_impl *impl,
    const char *b, 
    int size, 
    const transport::address &addr) {
    if (impl->cbs.read_from_cb) {
        impl->cbs.read_from_cb(impl, b, size, addr.ip().c_str(), (int)addr.port());
    }
}

static void on_transport_stopped(pump_c_transport_impl *impl) {
    if (impl->cbs.stopped_cb) {
        impl->cbs.stopped_cb(impl);
    }
}

static void on_transport_disconnected(pump_c_transport_impl *impl) {
    if (impl->cbs.disconnected_cb) {
        impl->cbs.disconnected_cb(impl);
    }
}

int pump_c_transport_start(
    pump_c_service sv,
    pump_c_transport transp, 
    struct pump_c_transport_callbacks cbs) {
    pump_c_service_impl *impl_sv = (pump_c_service_impl*)sv;
    PUMP_ASSERT(impl_sv && impl_sv->sv);

    pump_c_transport_impl *impl_transp = (pump_c_transport_impl*)transp;
    PUMP_ASSERT(impl_transp && impl_transp->transp);

    impl_transp->cbs = cbs;
    
    transport::transport_callbacks impl_cbs;
    impl_cbs.read_cb = pump_bind(on_transport_read, impl_transp, _1, _2);
    impl_cbs.read_from_cb = pump_bind(on_transport_read_from, impl_transp, _1, _2, _3);
    impl_cbs.stopped_cb = pump_bind(on_transport_stopped, impl_transp);
    impl_cbs.disconnected_cb = pump_bind(on_transport_disconnected, impl_transp);
    if (impl_transp->transp->start(impl_sv->sv, impl_cbs) != 0) {
        return -1;
    }

    return 0;
}

int pump_c_transport_stop(pump_c_transport transp) {
    pump_c_transport_impl *impl_transp = (pump_c_transport_impl*)transp;
    PUMP_ASSERT(impl_transp && impl_transp->transp);

    impl_transp->transp->stop();

    return 0;
}

int pump_c_transport_send(
    pump_c_transport transp, 
    const char *b, 
    int size) {
    pump_c_transport_impl *impl_transp = (pump_c_transport_impl*)transp;
    PUMP_ASSERT(impl_transp && impl_transp->transp);

    if (impl_transp->transp->send(b, size) <= 0) {
        return -1;
    }

    return 0;
}