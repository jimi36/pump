# Pump

The library is an asynchronous net library, callback based. It implement udp, tcp and tls transport. And tls is based on [gnutls](https://www.gnutls.org), but it is optional.

# Fetures

- Base callback.
- Post callback ability.
- Transport reading and writing separation.

# Build

The library is without tls transport as default. If you want it, you should turn on the gnutls option in CmakeLists.txt.  
To build the library, require [cmake](https://cmake.org/) and c++ compiler which support c++11.

## Window

On window, 2017 or higher version VS is required. First create vs project, then build the project:

```bash
mkdir build && cd build
cmake .. -G "Visual Studio 15 2017 Win64"
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

First of all, you should create and start the library service:
```c++
#include <pump/service.h>

 pump::service *sv = new pump::service;
 sv->start();
 ...
 sv->wait_stop();
```

## Acceptor

There are tcp and tls acceptors, they have the similar usage.

```c++
#include <pump/transports.h>

 class my_acceptor: 
    public pump::accepted_notifier,
    public std::enable_shared_from_this<my_acceptor>
 {
 protected:
    // transp is a new accepted tcp transport
    virtual void on_accepted_callback(void_ptr ctx, pump::transport_base_sptr transp)
    {
        ...
    }

    // accecptor stopped
    virtual void on_stopped_accepting_callback(void_ptr ctx)
    {
        ...
    }

    ...
 };

 ...

 // the lifetime of notifier must longer then the acceptor
 std::shared_ptr<pump::accepted_notifier> notifier(new my_acceptor);

 ...

 
 pump::tcp_acceptor_sptr acceptor = pump::tcp_acceptor::create_instance();
 acceptor->set_context(acceptor.get());

 pump::address listen_address("0.0.0.0", 8888);
 if (!acceptor->start(sv, listen_address, notifier))
 {
    printf("tcp acceptor start error\n");
 }

 ...

```

## Dialer

There are tcp and tls acceptors, they have the similar usage.

```c++
#include <pump/transports.h>

 class my_dialer:
    public pump::dialed_notifier,
    public std::enable_shared_from_this<my_dialer>
 {
 protected:
    // succ is dialed result 
    // transp is a new connected tcp transport
    virtual void on_dialed_callback(void_ptr ctx, pump::transport_base_sptr transp, bool succ)
    {
        ...
    }

    // dialed timeout
    virtual void on_dialed_timeout_callback(void_ptr ctx)
    {
        ...
    }

    // dialer stoppped
    virtual void on_stopped_dialing_callback(void_ptr ctx)
    {
        ...
    }

    ...
 };

 ...

 // the lifetime of notifier must longer then the dialer
 std::shared_ptr<pump::dialed_notifier> notifier(new my_dialer);

 ...

 pump::tcp_dialer_sptr dialer = pump::tcp_dialer::create_instance();
 dialer->set_context(dialer.get());

 pump::address bind_address("0.0.0.0", 8888);
 pump::address connect_address("127.0.0.1", 8887);
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

 class my_transport:
    public pump::transport_io_notifier,
    public pump::transport_terminated_notifier,
    public std::enable_shared_from_this<my_transport>
 {
 protected:
    // transport receive callback 
    virtual void on_recv_callback(pump::transport_base_ptr transp, pump::c_block_ptr b, int32 size)
    {
        ...
    }

    // transport sent data finish callback
    virtual void on_sent_callback(pump::transport_base_ptr transp)
    {
        ...
    }

    // transport disconnected
    virtual void on_disconnected_callback(pump::transport_base_ptr transp)
    {
        ...
    }

    // transport stopped
    virtual void on_stopped_callback(pump::transport_base_ptr transp)
    {
        ...
    }

    ...
 };

 ...

 // transp is tcp transport that created by accptor or dialer.
 pump::tcp_transport_sptr tcp_transp = static_pointer_cast<pump::tcp_transport>(transp);

 std::shared_ptr<my_transport> transp_notifier(new my_transport);
 pump::transport_io_notifier_sptr io_notifier = transp_notifier;
 pump::transport_terminated_notifier_sptr terminated_notifier = transp_notifier;
 if (!tcp_transp->start(sv, io_notifier, terminated_notifier))
 {
     printf("tcp transport start error\n");
 }

 ...
```

This is usage of udp transport:

```c++
#include <pump/transports.h>

 class my_udp_transport: 
    public pump::transport_io_notifier,
    public pump::transport_terminated_notifier,
    public std::enable_shared_from_this<my_udp_transport>
 {
 protected:
    // udp transport receive callback 
    virtual void on_recv_callback(pump::transport_base_ptr transp, pump::c_block_ptr b, int32 size, const pump::address &remote_address)
    {
        ...
    }

    // udp transport stopped
    virtual void on_stopped_callback(pump::transport_base_ptr transp)
    {
        ...
    }

    ...
 };

 ...

 std::shared_ptr<my_udp_transport> my_transport(new my_udp_transport);

 pump::address localaddr("0.0.0.0", 8888);
 pump::transport_io_notifier_sptr io_notifier = my_transport;
 pump::transport_terminated_notifier_sptr terminated_notifier = my_transport;
 pump::udp_transport_sptr transp = pump::udp_transport::create_instance();
 if (!transp->start(sv, localaddr, io_notifier, terminated_notifier))
 {
    printf("udp transport start error\n");
 }
```