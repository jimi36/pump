# Pump

The library is an asynchronous net library, callback based. It implement udp, tcp and tls transport. And tls is based on [gnutls](https://www.gnutls.org), but it is optional.

# Fetures

- Timer based on callback.
- Transport are read-write separated and thread-safe. We use free lock queue to improve transport performance.
- Tls and tcp transport provide a simple speed control function.
- Supports windows and linux os.

# Build

If you want tls transport, you should turn on the gnutls option in CmakeLists.txt. Also jemalloc is supported, but it is not default, jemalloc option should be turned on in Cmakelists.txt if you want.  
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

## Post function task
After service started, you can post function tasks to service. Then function tasks will be called in order by service. 
```c++

void print_task()
{
    printf("hello world\n");
}

sv->post(function::bind(&print_task));

```

## Timer
When timer is stopped or timeout, the timer should no be used again if it is not repeated.
```c++

// timeout callback
void on_timeout_callback()
{
	printf("timeout at %llus\n", ::time(0));
}

// create a repeated timer with 1s timeout time
pump::time::timer_callback cb = function::bind(&on_timer_timeout);
pump::time::timer_sptr timer(new pump::time::timer(cb, 1000, true));
if (!sv_->start_timer(timer))
{
	printf("start timeout error\n");
}

```

## Acceptor

There are tcp and tls acceptors, they have the similar usage.

```c++
#include <pump/transports.h>

// transp is a new accepted tcp transport
void on_accepted_callback(pump::transport_base_sptr transp)
{
    ...
}

// accecptor stopped
void on_stopped_callback()
{
    ...
}

...

pump::acceptor_callbacks cbs;
cbs.accepted_cb = function::bind(&on_accepted_callback, _1);
cbs.stopped_cb = function::bind(&on_stopped_callback);

pump::address listen_address("0.0.0.0", 8888);
pump::tcp_acceptor_sptr acceptor = pump::tcp_acceptor::create_instance(listen_address);

if (!acceptor->start(sv, cbs))
{
    printf("tcp acceptor start error\n");
}

...
```

## Dialer

There are tcp and tls acceptors, they have the similar usage.

```c++
#include <pump/transports.h>

// succ is dialed result 
// transp is a new connected tcp transport
void on_dialed_callback(pump::transport_base_sptr transp, bool succ)
{
    ...
}

// dialed timeout
void on_dial_timeout_callback()
{
    ...
}

// dialer stoppped
void on_dial_stopped_callback()
{
    ...
}

...

pump::dialer_callbacks cbs;
cbs.dialed_cb = function::bind(&on_dialed_callback, _1, _2);
cbs.stopped_cb = function::bind(&on_dial_stopped_callback);
cbs.timeout_cb = function::bind(&on_dial_timeout_callback);

pump::address local_address("0.0.0.0", 8888);
pump::address remote_address("127.0.0.1", 8887);
pump::tcp_dialer_sptr dialer = pump::tcp_dialer::create_instance(local_address, remote_address);

if (!dialer->start(sv, 0, bind_address, connect_address, notifier))
{
    printf("tcp dialer start error\n");
}

...
```

## Transport

There are tcp and tls transports, they have the similar usage.

```c++
#include <pump/transports.h>

// transport read callback 
void on_read_callback(pump::c_block_ptr b, int32 size)
{
    ...
}

// transport disconnected
void on_disconnected_callback()
{
    ...
}

// transport stopped
void on_stopped_callback()
{
    ...
}

...

// transp is tcp transport that created by accptor or dialer.
void on_new_transport(pump::base_transport_sptr transp)
{
	pump::transport_callbacks cbs;
	cbs.read_cb = function::bind(&on_read_callback, _1, _2);
	cbs.stopped_cb = function::bind(&on_stopped_callback);
	cbs.disconnected_cb = function::bind(&on_disconnected_callback);

    if (!transp->start(sv, 0, cbs))
    {
        printf("transport start error\n");
    }
}

...
```

This is usage of udp transport:

```c++
#include <pump/transports.h>

// udp transport read callback 
void on_read_callback(pump::c_block_ptr b, int32 size, const pump::address &remote_address)
{
    ...
}

// udp transport stopped
void on_stopped_callback()
{
    ...
}

...

pump::transport_callbacks cbs;
cbs.read_from_cb = function::bind(&on_read_callback, _1, _2, _3);
cbs.stopped_cb = function::bind(&on_stopped_callback);

pump::address local_address("0.0.0.0", 8888);
pump::udp_transport_sptr transp = pump::udp_transport::create_instance(local_address);
if (!transp->start(sv, 0, cbs))
{
    printf("udp transport start error\n");
}

...
```