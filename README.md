# Pump

The library is an asynchronous net library, callback based. It implement udp, tcp, tls transport, timer and function event. Support openssl and gnutls.

# Fetures

- Support read-write separated for transport.
- Use free lock queue to improve transport performance.
- Provide a simple speed control function on tls and tcp transport.
- High throughput (using epoll and iocp).
- Cross platform (windows, linux).

# Build

Support tls transport, but not default. You can set WITH_TLS to turn on it.  
Support jemalloc, but not default. You can turn on WITH_JEMALLOC option to support it.  
To build the library, require [cmake](https://cmake.org/) and c++ compiler which support c++11.

## Window

On window, 2017 or higher version VS is required. First create vs project, then build the project:

```bash
mkdir build && cd build
cmake .. -G "Visual Studio 15 2017"
pump_main.sln
```

## Linux

On linux, gcc and g++ is required and must support c++11. Build the library:

```bash
mkdir build && cd build
cmake .. && make
```

# Usage

## Service

First of all, you should create and start the library service. And then wait_stopped function will block current thread until service stopped. By the way all transports and timers should be stopped before stopping serivce, otherwise serivce will block at wait_stopped for ever.
```c++
#include <pump/service.h>

 pump::service_ptr sv = new pump::service;
 sv->start();

 ...
 
 sv->wait_stopped();
```

## Post function event
After service started, you can post function event to service. Then function event will be called in order by service. 
```c++
#include <pump/service.h>
#include <pump/time/timer.h>

void print_task() {
    printf("hello world\n");
}

sv->post(pump_bind(&print_task));

```

## Timer
When timer is stopped or timeout, the timer should no be used again if it is not repeated.
```c++
using namespace pump;

// timeout callback
void on_timeout_callback() {
	printf("timeout at %llus\n", ::time(0));
}

// create a repeated timer with 1s timeout time
pump::time::timer_callback cb = pump_bind(&on_timer_timeout);
pump::time::timer_sptr timer = pump::time::timer::create(cb, 1000, true);
if (!sv_->start_timer(timer)) {
	printf("start timeout error\n");
}

```

## Acceptor

There are tcp and tls acceptors, they have the similar usage.

```c++
#include <pump/service.h>
#include <pump/transport/tcp_acceptor.h>
#include <pump/transport/tcp_transport.h>

using namespace pump;

// transp is a new accepted tcp transport
void on_accepted_callback(transport::transport_base_sptr transp) {
    ...
}

// accecptor stopped
void on_stopped_callback() {
    ...
}

...

transport::acceptor_callbacks cbs;
cbs.accepted_cb = pump_bind(&on_accepted_callback, _1);
cbs.stopped_cb = pump_bind(&on_stopped_callback);

transport::address listen_address("0.0.0.0", 8888);
transport::tcp_acceptor_sptr acceptor = transport::tcp_acceptor::create(listen_address);
if (acceptor->start(sv, cbs) != transport::ERROR_OK) {
    printf("tcp acceptor start error\n");
}

...
```

## Dialer

There are tcp and tls acceptors, they have the similar usage.

```c++
#include <pump/service.h>
#include <pump/transport/tcp_dialer.h>
#include <pump/transport/tcp_transport.h>

using namespace pump;

// succ is dialed result 
// transp is a new connected tcp transport
void on_dialed_callback(transport::transport_base_sptr transp, bool succ) {
    ...
}

// dialed timeout
void on_dial_timeout_callback() {
    ...
}

// dialer stoppped
void on_dial_stopped_callback() {
    ...
}

...

transport::dialer_callbacks cbs;
cbs.dialed_cb = pump_bind(&on_dialed_callback, _1, _2);
cbs.stopped_cb = pump_bind(&on_dial_stopped_callback);
cbs.timeout_cb = pump_bind(&on_dial_timeout_callback);

transport::address local_address("0.0.0.0", 8888);
transport::address remote_address("127.0.0.1", 8887);
transport::tcp_dialer_sptr dialer = transport::tcp_dialer::create(local_address, remote_address, 1000);
if (dialer->start(sv, cbs) != transport::ERROR_OK) {
    printf("tcp dialer start error\n");
}

...
```

## Transport

There are tcp and tls transports, they have the similar usage.

```c++
#include <pump/service.h>
#include <pump/transport/tcp_transport.h>

using namespace pump;

// transport read callback 
void on_read_callback(c_block_ptr b, int32 size) {
    ...
}

// transport disconnected
void on_disconnected_callback() {
    ...
}

// transport stopped
void on_stopped_callback() {
    ...
}

...

// transp is tcp transport that created by accptor or dialer.
void on_new_transport(transport::base_transport_sptr transp)
{
    transport::transport_callbacks cbs;
    cbs.read_cb = pump_bind(&on_read_callback, _1, _2);
    cbs.stopped_cb = pump_bind(&on_stopped_callback);
    cbs.disconnected_cb = pump_bind(&on_disconnected_callback);
    if (transp->start(sv, 0, cbs) != transport::ERROR_OK) {
        printf("transport start error\n");
    }
}

...
```
